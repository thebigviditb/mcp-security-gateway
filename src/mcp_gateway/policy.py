"""Method-level authorization policy for MCP JSON-RPC messages."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .auth import Principal
from .config import Settings
from .jsonrpc import method_of, tool_name_of


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""
    #: Populated on denial so the error `data` can name the offending tool.
    tool: str | None = None


ALLOW = Decision(allowed=True)


class ToolPolicy:
    """Decides whether a principal may send a given JSON-RPC message upstream.

    The rule set is intentionally small and explicit:

    * ``tools/call`` for a tool named ``<admin_prefix>*`` requires the admin role.
    * every other message -- ``tools/list``, ``initialize``, notifications,
      non-admin tool calls -- is forwarded transparently.

    Anything the gateway cannot evaluate (a ``tools/call`` with no usable
    ``params.name``) is left to the downstream server, which owns param
    validation and will reject it with -32602.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def is_admin_tool(self, name: str) -> bool:
        return name.startswith(self._settings.admin_prefix)

    def evaluate(self, message: Any, principal: Principal) -> Decision:
        if method_of(message) != "tools/call":
            return ALLOW

        name = tool_name_of(message)
        if name is None or not self.is_admin_tool(name):
            return ALLOW

        if principal.has_role(self._settings.admin_role):
            return ALLOW

        return Decision(
            allowed=False,
            reason=(
                f"Tool {name!r} requires the "
                f"{self._settings.admin_role!r} role; token has "
                f"{principal.role!r}"
            ),
            tool=name,
        )

    def visible_tools(self, tools: list[Any], principal: Principal) -> list[Any]:
        """Filter a `tools/list` result for `principal`.

        Only used when `Settings.filter_tools_list` is enabled.
        """
        if principal.has_role(self._settings.admin_role):
            return tools
        return [
            tool
            for tool in tools
            if not (
                isinstance(tool, dict)
                and isinstance(tool.get("name"), str)
                and self.is_admin_tool(tool["name"])
            )
        ]
