"""A mock downstream MCP server.

Deliberately unaware of roles and tokens: it trusts whatever reaches it, which
is exactly why the gateway in front of it has to be correct.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from .jsonrpc import (
    INVALID_REQUEST,
    error_response,
    is_notification,
    is_request_object,
)

PROTOCOL_VERSION = "2025-06-18"

TOOLS: list[dict[str, Any]] = [
    {
        "name": "search_orders",
        "description": "Search orders by customer id.",
        "inputSchema": {
            "type": "object",
            "properties": {"customer_id": {"type": "string"}},
            "required": ["customer_id"],
        },
    },
    {
        "name": "admin_reset_key",
        "description": "Rotate the tenant API key. Admin only.",
        "inputSchema": {
            "type": "object",
            "properties": {"tenant": {"type": "string"}},
            "required": ["tenant"],
        },
    },
    {
        "name": "admin_delete_tenant",
        "description": "Permanently delete a tenant. Admin only.",
        "inputSchema": {
            "type": "object",
            "properties": {"tenant": {"type": "string"}},
            "required": ["tenant"],
        },
    },
]

TOOLS_BY_NAME = {tool["name"]: tool for tool in TOOLS}


def _text_result(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": False}


def _handle(message: Any) -> dict[str, Any] | None:
    """Handle one JSON-RPC message; None means "no response" (notification)."""
    if not is_request_object(message):
        return error_response(None, INVALID_REQUEST, "Invalid Request")
    if is_notification(message):
        return None

    rid = message.get("id")
    method = message["method"]
    params = message.get("params") or {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "mock-mcp-server", "version": "0.1.0"},
            },
        }

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}

    if method == "tools/call":
        name = params.get("name") if isinstance(params, dict) else None
        if not isinstance(name, str):
            return error_response(rid, -32602, "Invalid params", "params.name is required")
        if name not in TOOLS_BY_NAME:
            return error_response(rid, -32602, "Invalid params", f"Unknown tool: {name}")
        arguments = params.get("arguments") or {}
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "result": _text_result(f"{name} executed with {arguments}"),
        }

    return error_response(rid, -32601, "Method not found", method)


def create_app() -> FastAPI:
    app = FastAPI(title="Mock MCP Server", version="0.1.0")

    @app.post("/mcp")
    async def mcp(request: Request) -> Response:
        payload = await request.json()
        if isinstance(payload, list):
            responses = [r for r in (_handle(m) for m in payload) if r is not None]
            return JSONResponse(responses) if responses else Response(status_code=202)
        response = _handle(payload)
        return JSONResponse(response) if response is not None else Response(status_code=202)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
