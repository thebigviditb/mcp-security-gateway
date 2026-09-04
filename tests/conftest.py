from __future__ import annotations

import httpx
import pytest
import pytest_asyncio

from mcp_gateway.config import Settings
from mcp_gateway.downstream import create_app as create_downstream
from mcp_gateway.gateway import create_app as create_gateway

UPSTREAM_URL = "http://downstream.test/mcp"

ADMIN = {"Authorization": "Bearer admin-token"}
VIEWER = {"Authorization": "Bearer viewer-token"}


@pytest.fixture
def settings() -> Settings:
    return Settings(upstream_url=UPSTREAM_URL)


@pytest_asyncio.fixture
async def upstream_client() -> httpx.AsyncClient:
    """An httpx client wired straight into the in-process mock server."""
    transport = httpx.ASGITransport(app=create_downstream())
    async with httpx.AsyncClient(transport=transport) as client:
        yield client


@pytest_asyncio.fixture
async def gateway(settings, upstream_client) -> httpx.AsyncClient:
    app = create_gateway(settings=settings, client=upstream_client)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://gateway.test"
    ) as client:
        # Trigger the lifespan so app.state.client is populated.
        async with app.router.lifespan_context(app):
            yield client


def rpc(method: str, *, rid=1, **params) -> dict:
    message = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params:
        message["params"] = params
    return message


def call(name: str, *, rid=1, **arguments) -> dict:
    return rpc("tools/call", rid=rid, name=name, arguments=arguments)
