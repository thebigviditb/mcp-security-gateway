"""Minimal JSON-RPC 2.0 wire-format helpers.

The gateway only needs to *understand* the envelope well enough to route and
authorize; it deliberately does not validate anything the downstream server is
better placed to validate (unknown methods, param schemas, ...).
"""

from __future__ import annotations

from typing import Any

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
INTERNAL_ERROR = -32603

#: Custom, gateway-specific code from the implementation-defined range.
UNAUTHORIZED_TOOL_CALL = -32001
#: Returned when the downstream server cannot be reached or misbehaves.
UPSTREAM_ERROR = -32002


def error_response(
    request_id: Any,
    code: int,
    message: str,
    data: Any | None = None,
) -> dict[str, Any]:
    """Build a JSON-RPC error response object."""
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def is_request_object(message: Any) -> bool:
    """True if `message` is structurally a JSON-RPC request or notification."""
    return (
        isinstance(message, dict)
        and message.get("jsonrpc") == "2.0"
        and isinstance(message.get("method"), str)
    )


def is_notification(message: Any) -> bool:
    """Notifications carry no `id` and therefore MUST NOT be answered."""
    return is_request_object(message) and "id" not in message


def request_id(message: Any) -> Any:
    """The `id` of a request, or None for notifications / malformed input.

    A null id is the correct id to echo back when the request itself could not
    be parsed, per the JSON-RPC 2.0 spec.
    """
    if isinstance(message, dict):
        rid = message.get("id")
        # Only str/int/None are valid ids on the wire; anything else is junk.
        if isinstance(rid, (str, int)) and not isinstance(rid, bool):
            return rid
    return None


def method_of(message: Any) -> str | None:
    return message.get("method") if is_request_object(message) else None


def tool_name_of(message: Any) -> str | None:
    """`params.name` for a `tools/call`, if present and well-formed."""
    if not is_request_object(message):
        return None
    params = message.get("params")
    if not isinstance(params, dict):
        return None
    name = params.get("name")
    return name if isinstance(name, str) else None
