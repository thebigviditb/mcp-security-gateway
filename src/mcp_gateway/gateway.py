"""The MCP security gateway: an authorizing reverse proxy for MCP over HTTP."""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from typing import Any, Iterable

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.background import BackgroundTask

from .auth import AuthError, Principal, TokenResolver, authenticate
from .config import Settings
from .jsonrpc import (
    INVALID_REQUEST,
    PARSE_ERROR,
    UNAUTHORIZED_TOOL_CALL,
    UPSTREAM_ERROR,
    error_response,
    is_notification,
    is_request_object,
    method_of,
    request_id,
)
from .policy import ToolPolicy

logger = logging.getLogger("mcp_gateway")

#: Connection-specific headers that must not be relayed by a proxy (RFC 9110).
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
#: Additionally dropped on the way upstream: recomputed or replaced by us.
STRIP_REQUEST_HEADERS = HOP_BY_HOP | {"host", "content-length", "authorization"}
#: Additionally dropped on the way back when we rewrite the body.
STRIP_REWRITTEN_RESPONSE_HEADERS = HOP_BY_HOP | {"content-length", "content-encoding"}


def _forwardable_request_headers(request: Request, principal: Principal) -> dict[str, str]:
    """Client headers to relay upstream, plus the resolved identity."""
    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in STRIP_REQUEST_HEADERS
    }
    # Do not let the client dictate a transfer encoding we cannot honour.
    headers.setdefault("accept-encoding", "identity")
    # The downstream server sees who the gateway authenticated, never the
    # caller's raw token.
    headers["x-mcp-gateway-role"] = principal.role
    return headers


def _passthrough_response_headers(headers: httpx.Headers, drop: Iterable[str]) -> list[tuple[str, str]]:
    drop = {name.lower() for name in drop}
    return [(k, v) for k, v in headers.multi_items() if k.lower() not in drop]


def _unauthorized_error(message: Any, reason: str, tool: str | None) -> dict[str, Any]:
    return error_response(
        request_id(message),
        UNAUTHORIZED_TOOL_CALL,
        "Unauthorized Tool Call",
        data={"reason": reason, "tool": tool},
    )


def create_app(
    settings: Settings | None = None,
    client: httpx.AsyncClient | None = None,
) -> FastAPI:
    """Build the gateway app.

    `client` is injectable so tests can wire the gateway straight to an
    in-process downstream server without opening a socket.
    """
    settings = settings or Settings.from_env()
    policy = ToolPolicy(settings)
    resolver = TokenResolver(settings.tokens)
    owns_client = client is None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.client = client or httpx.AsyncClient(
            timeout=settings.upstream_timeout_seconds
        )
        try:
            yield
        finally:
            if owns_client:
                await app.state.client.aclose()

    app = FastAPI(title="MCP Security Gateway", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.policy = policy

    def _auth(request: Request) -> Principal:
        return authenticate(request.headers.get("authorization"), resolver)

    @app.exception_handler(AuthError)
    async def _auth_error_handler(_: Request, exc: AuthError) -> JSONResponse:
        # Transport-level failure: HTTP 401 with a challenge, per the MCP
        # authorization spec. It is not attributable to a single JSON-RPC id.
        return JSONResponse(
            status_code=401,
            content={"error": exc.error, "error_description": exc.message},
            headers={
                "WWW-Authenticate": f'Bearer error="{exc.error}", '
                f'error_description="{exc.message}"'
            },
        )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "upstream": settings.upstream_url}

    @app.post("/mcp")
    async def proxy_post(request: Request) -> Response:
        principal = _auth(request)
        raw = await request.body()

        try:
            payload = json.loads(raw) if raw else None
        except json.JSONDecodeError as exc:
            return _jsonrpc_error(PARSE_ERROR, "Parse error", str(exc))

        batch = isinstance(payload, list)
        messages = payload if batch else [payload]
        if (batch and not messages) or not all(
            is_request_object(m) for m in messages
        ):
            return _jsonrpc_error(
                INVALID_REQUEST,
                "Invalid Request",
                "Payload is not a JSON-RPC 2.0 request or batch",
                rid=None if batch else request_id(payload),
            )

        # --- authorization ------------------------------------------------
        allowed: list[Any] = []
        intercepted: list[dict[str, Any]] = []
        for message in messages:
            decision = policy.evaluate(message, principal)
            if decision.allowed:
                allowed.append(message)
                continue
            logger.warning(
                "blocked %s tool=%s role=%s", method_of(message), decision.tool, principal.role
            )
            # A denied notification expects no reply -- drop it silently.
            if not is_notification(message):
                intercepted.append(
                    _unauthorized_error(message, decision.reason, decision.tool)
                )

        if not allowed:
            # Nothing survives policy: answer without ever touching upstream.
            if not intercepted:
                return Response(status_code=202)
            return JSONResponse(intercepted if batch else intercepted[0])

        rewriting = len(allowed) != len(messages) or _needs_result_filtering(
            settings, allowed, principal
        )
        headers = _forwardable_request_headers(request, principal)

        if not rewriting:
            # Fully transparent path: relay the exact bytes we were given and
            # stream the response back, so SSE responses keep working.
            return await _stream_upstream(request, headers, raw)

        # We must merge intercepted errors and/or filter results, so ask the
        # downstream server for a single JSON document rather than a stream.
        headers["accept"] = "application/json"
        body = json.dumps(allowed if batch else allowed[0]).encode()
        try:
            upstream = await request.app.state.client.post(
                settings.upstream_url, content=body, headers=headers
            )
        except httpx.HTTPError as exc:
            return _upstream_failure(exc)

        return _merge_upstream(
            upstream, intercepted, batch, settings, policy, principal, allowed
        )

    @app.get("/mcp")
    async def proxy_get(request: Request) -> Response:
        """Server-to-client SSE stream. No JSON-RPC payload to authorize."""
        principal = _auth(request)
        return await _stream_upstream(
            request, _forwardable_request_headers(request, principal), None, method="GET"
        )

    @app.delete("/mcp")
    async def proxy_delete(request: Request) -> Response:
        """Session termination."""
        principal = _auth(request)
        return await _stream_upstream(
            request, _forwardable_request_headers(request, principal), None, method="DELETE"
        )

    async def _stream_upstream(
        request: Request,
        headers: dict[str, str],
        content: bytes | None,
        method: str = "POST",
    ) -> Response:
        client: httpx.AsyncClient = request.app.state.client
        upstream_request = client.build_request(
            method,
            settings.upstream_url,
            headers=headers,
            content=content,
            params=dict(request.query_params),
        )
        try:
            upstream = await client.send(upstream_request, stream=True)
        except httpx.HTTPError as exc:
            return _upstream_failure(exc)
        return StreamingResponse(
            _raw_chunks(upstream),
            status_code=upstream.status_code,
            headers=dict(_passthrough_response_headers(upstream.headers, HOP_BY_HOP)),
            background=BackgroundTask(upstream.aclose),
        )

    return app


async def _raw_chunks(response: httpx.Response):
    """Yield the response body without re-decoding it.

    Some transports (mocks, short-circuits) hand back a fully buffered response;
    `aiter_raw` would reject those, so fall back to the buffered content.
    """
    if response.is_stream_consumed:
        yield response.content
        return
    async for chunk in response.aiter_raw():
        yield chunk


def _jsonrpc_error(
    code: int, message: str, detail: str | None = None, rid: Any = None
) -> JSONResponse:
    # JSON-RPC-level failures are returned with HTTP 200; the error lives in the
    # envelope where the client's JSON-RPC layer expects it.
    return JSONResponse(error_response(rid, code, message, detail))


def _upstream_failure(exc: httpx.HTTPError) -> JSONResponse:
    logger.error("upstream request failed: %s", exc)
    return JSONResponse(
        status_code=502,
        content=error_response(None, UPSTREAM_ERROR, "Upstream server unavailable", str(exc)),
    )


def _needs_result_filtering(
    settings: Settings, messages: list[Any], principal: Principal
) -> bool:
    if not settings.filter_tools_list or principal.has_role(settings.admin_role):
        return False
    return any(method_of(m) == "tools/list" for m in messages)


def _merge_upstream(
    upstream: httpx.Response,
    intercepted: list[dict[str, Any]],
    batch: bool,
    settings: Settings,
    policy: ToolPolicy,
    principal: Principal,
    forwarded: list[Any],
) -> Response:
    """Splice downstream responses together with locally generated errors."""
    if upstream.status_code >= 400 and not intercepted:
        # Nothing of ours to merge in; relay the failure verbatim.
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=dict(_passthrough_response_headers(upstream.headers, HOP_BY_HOP)),
        )

    try:
        body = upstream.json()
    except ValueError:
        return JSONResponse(
            status_code=502,
            content=error_response(
                None,
                UPSTREAM_ERROR,
                "Upstream returned a non-JSON response",
                {"status": upstream.status_code},
            ),
        )

    responses = body if isinstance(body, list) else [body]
    if settings.filter_tools_list:
        list_ids = {
            request_id(m) for m in forwarded if method_of(m) == "tools/list"
        }
        responses = [
            _filter_tools_result(r, policy, principal)
            if request_id(r) in list_ids
            else r
            for r in responses
        ]

    merged = responses + intercepted
    return JSONResponse(
        merged if batch else merged[0],
        status_code=upstream.status_code,
        headers=dict(
            _passthrough_response_headers(upstream.headers, STRIP_REWRITTEN_RESPONSE_HEADERS)
        ),
    )


def _filter_tools_result(
    response: Any, policy: ToolPolicy, principal: Principal
) -> Any:
    if not isinstance(response, dict):
        return response
    result = response.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
        return response
    return {
        **response,
        "result": {**result, "tools": policy.visible_tools(result["tools"], principal)},
    }
