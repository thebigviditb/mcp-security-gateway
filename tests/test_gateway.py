"""End-to-end tests: agent client -> gateway -> mock MCP server."""

from __future__ import annotations

import httpx
import pytest

from mcp_gateway.config import Settings
from mcp_gateway.downstream import create_app as create_downstream
from mcp_gateway.gateway import create_app as create_gateway
from mcp_gateway.jsonrpc import UNAUTHORIZED_TOOL_CALL

from conftest import ADMIN, UPSTREAM_URL, VIEWER, call, rpc


# --- authentication -------------------------------------------------------


async def test_missing_authorization_header_is_rejected(gateway):
    response = await gateway.post("/mcp", json=rpc("tools/list"))
    assert response.status_code == 401
    assert "Bearer" in response.headers["www-authenticate"]


@pytest.mark.parametrize(
    "header",
    ["Basic admin-token", "Bearer ", "bearer unknown-token", "admin-token"],
)
async def test_unusable_credentials_are_rejected(gateway, header):
    response = await gateway.post(
        "/mcp", json=rpc("tools/list"), headers={"Authorization": header}
    )
    assert response.status_code == 401


async def test_bearer_scheme_is_case_insensitive(gateway):
    response = await gateway.post(
        "/mcp", json=rpc("tools/list"), headers={"Authorization": "bEaReR admin-token"}
    )
    assert response.status_code == 200


# --- transparent forwarding ----------------------------------------------


@pytest.mark.parametrize("headers", [ADMIN, VIEWER], ids=["admin", "viewer"])
async def test_tools_list_is_forwarded_for_every_role(gateway, headers):
    response = await gateway.post("/mcp", json=rpc("tools/list", rid="a"), headers=headers)
    body = response.json()

    assert response.status_code == 200
    assert body["id"] == "a"
    names = [tool["name"] for tool in body["result"]["tools"]]
    # Forwarded transparently: even the viewer sees the admin tools listed.
    assert "admin_reset_key" in names and "search_orders" in names


async def test_initialize_is_forwarded_untouched(gateway):
    response = await gateway.post("/mcp", json=rpc("initialize"), headers=VIEWER)
    assert response.json()["result"]["serverInfo"]["name"] == "mock-mcp-server"


async def test_non_admin_tool_call_reaches_downstream(gateway):
    response = await gateway.post(
        "/mcp", json=call("search_orders", customer_id="c-1"), headers=VIEWER
    )
    result = response.json()["result"]
    assert "search_orders executed" in result["content"][0]["text"]


async def test_downstream_errors_are_relayed_unchanged(gateway):
    response = await gateway.post("/mcp", json=call("does_not_exist"), headers=ADMIN)
    assert response.json()["error"]["code"] == -32602


# --- authorization --------------------------------------------------------


async def test_admin_tool_is_blocked_for_viewer(gateway):
    response = await gateway.post(
        "/mcp", json=call("admin_reset_key", rid=7, tenant="acme"), headers=VIEWER
    )
    body = response.json()

    assert response.status_code == 200
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == 7  # the id is echoed back so the client can correlate
    assert body["error"]["code"] == UNAUTHORIZED_TOOL_CALL
    assert body["error"]["message"] == "Unauthorized Tool Call"
    assert body["error"]["data"]["tool"] == "admin_reset_key"
    assert "result" not in body


async def test_admin_tool_is_allowed_for_admin(gateway):
    response = await gateway.post(
        "/mcp", json=call("admin_reset_key", tenant="acme"), headers=ADMIN
    )
    assert "admin_reset_key executed" in response.json()["result"]["content"][0]["text"]


async def test_blocked_call_never_reaches_downstream(settings):
    """The whole point: a denied call must not touch the downstream server."""
    seen: list[bytes] = []

    async def spy(request: httpx.Request) -> httpx.Response:
        seen.append(request.content)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    app = create_gateway(
        settings=settings, client=httpx.AsyncClient(transport=httpx.MockTransport(spy))
    )
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://gateway.test"
        ) as client:
            await client.post("/mcp", json=call("admin_reset_key"), headers=VIEWER)

    assert seen == []


async def test_unknown_role_cannot_reach_admin_tools():
    """A valid token with an unrecognised role is treated as non-admin."""
    settings = Settings(
        upstream_url=UPSTREAM_URL, tokens={"ops-token": "operator"}
    )
    upstream = httpx.AsyncClient(transport=httpx.ASGITransport(app=create_downstream()))
    app = create_gateway(settings=settings, client=upstream)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
        ) as client:
            response = await client.post(
                "/mcp",
                json=call("admin_reset_key"),
                headers={"Authorization": "Bearer ops-token"},
            )
    assert response.json()["error"]["code"] == UNAUTHORIZED_TOOL_CALL


@pytest.mark.parametrize(
    "name", ["admin_reset_key", "admin_delete_tenant", "admin_"]
)
async def test_every_admin_prefixed_tool_is_gated(gateway, name):
    response = await gateway.post("/mcp", json=call(name), headers=VIEWER)
    assert response.json()["error"]["code"] == UNAUTHORIZED_TOOL_CALL


@pytest.mark.parametrize("name", ["administer_users", "not_admin_reset", "ADMIN_RESET"])
async def test_lookalike_names_are_not_treated_as_admin_tools(gateway, name):
    """Only an exact prefix match gates a tool -- and it never fails open."""
    response = await gateway.post("/mcp", json=call(name), headers=VIEWER)
    # Reached downstream, which rejects them as unknown tools.
    assert response.json()["error"]["code"] == -32602


async def test_configurable_admin_prefix(upstream_client):
    settings = Settings(upstream_url=UPSTREAM_URL, admin_prefix="admin_delete_")
    app = create_gateway(settings=settings, client=upstream_client)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
        ) as client:
            blocked = await client.post(
                "/mcp", json=call("admin_delete_tenant"), headers=VIEWER
            )
            allowed = await client.post(
                "/mcp", json=call("admin_reset_key"), headers=VIEWER
            )
    assert blocked.json()["error"]["code"] == UNAUTHORIZED_TOOL_CALL
    assert "result" in allowed.json()


# --- malformed wire format ------------------------------------------------


async def test_invalid_json_returns_parse_error(gateway):
    response = await gateway.post(
        "/mcp",
        content=b"{not json",
        headers={**ADMIN, "Content-Type": "application/json"},
    )
    assert response.json()["error"]["code"] == -32700


@pytest.mark.parametrize(
    "payload",
    [
        {"method": "tools/list", "id": 1},  # missing jsonrpc
        {"jsonrpc": "1.0", "method": "tools/list", "id": 1},  # wrong version
        {"jsonrpc": "2.0", "id": 1},  # missing method
        [],  # empty batch
        "hello",  # not an object at all
    ],
)
async def test_malformed_envelopes_return_invalid_request(gateway, payload):
    response = await gateway.post("/mcp", json=payload, headers=ADMIN)
    assert response.json()["error"]["code"] == -32600


async def test_tools_call_without_a_name_is_left_to_downstream(gateway):
    """The gateway cannot evaluate it, so it must not silently allow or block."""
    response = await gateway.post(
        "/mcp", json=rpc("tools/call", arguments={}), headers=VIEWER
    )
    assert response.json()["error"]["code"] == -32602


# --- notifications and batches -------------------------------------------


async def test_notification_is_forwarded_and_gets_no_body(gateway):
    response = await gateway.post(
        "/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=ADMIN
    )
    assert response.status_code == 202
    assert response.content == b""


async def test_blocked_notification_is_dropped_without_a_response(gateway):
    response = await gateway.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "admin_reset_key"},
        },
        headers=VIEWER,
    )
    assert response.status_code == 202
    assert response.content == b""


async def test_batch_is_partially_blocked(gateway):
    batch = [
        rpc("tools/list", rid="list"),
        call("admin_reset_key", rid="blocked", tenant="acme"),
        call("search_orders", rid="ok", customer_id="c-1"),
    ]
    response = await gateway.post("/mcp", json=batch, headers=VIEWER)
    by_id = {item["id"]: item for item in response.json()}

    assert set(by_id) == {"list", "blocked", "ok"}
    assert by_id["blocked"]["error"]["code"] == UNAUTHORIZED_TOOL_CALL
    assert "result" in by_id["list"]
    assert "result" in by_id["ok"]  # the allowed calls still ran


async def test_fully_blocked_batch_skips_downstream_entirely(settings):
    async def spy(request: httpx.Request) -> httpx.Response:
        raise AssertionError("downstream must not be called")

    app = create_gateway(
        settings=settings, client=httpx.AsyncClient(transport=httpx.MockTransport(spy))
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
        ) as client:
            response = await client.post(
                "/mcp",
                json=[call("admin_reset_key", rid=1), call("admin_delete_tenant", rid=2)],
                headers=VIEWER,
            )
    body = response.json()
    assert [item["id"] for item in body] == [1, 2]
    assert all(item["error"]["code"] == UNAUTHORIZED_TOOL_CALL for item in body)


# --- proxy behaviour ------------------------------------------------------


async def test_identity_is_passed_downstream_and_token_is_not(settings):
    captured: dict[str, httpx.Headers] = {}

    async def spy(request: httpx.Request) -> httpx.Response:
        captured["headers"] = request.headers
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    app = create_gateway(
        settings=settings, client=httpx.AsyncClient(transport=httpx.MockTransport(spy))
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
        ) as client:
            await client.post(
                "/mcp",
                json=rpc("tools/list"),
                headers={**VIEWER, "Mcp-Session-Id": "session-42"},
            )

    headers = captured["headers"]
    assert headers["x-mcp-gateway-role"] == "viewer"
    assert headers["mcp-session-id"] == "session-42"  # session affinity preserved
    assert "authorization" not in headers  # the caller's token is never relayed


async def test_upstream_failure_becomes_a_502_jsonrpc_error(settings):
    async def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    app = create_gateway(
        settings=settings, client=httpx.AsyncClient(transport=httpx.MockTransport(boom))
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
        ) as client:
            response = await client.post("/mcp", json=rpc("tools/list"), headers=ADMIN)

    assert response.status_code == 502
    assert response.json()["error"]["code"] == -32002


async def test_tools_list_filtering_when_enabled(upstream_client):
    settings = Settings(upstream_url=UPSTREAM_URL, filter_tools_list=True)
    app = create_gateway(settings=settings, client=upstream_client)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
        ) as client:
            viewer = await client.post("/mcp", json=rpc("tools/list"), headers=VIEWER)
            admin = await client.post("/mcp", json=rpc("tools/list"), headers=ADMIN)

    viewer_names = [t["name"] for t in viewer.json()["result"]["tools"]]
    admin_names = [t["name"] for t in admin.json()["result"]["tools"]]
    assert viewer_names == ["search_orders"]
    assert "admin_reset_key" in admin_names


async def test_healthz(gateway):
    assert (await gateway.get("/healthz")).json()["status"] == "ok"
