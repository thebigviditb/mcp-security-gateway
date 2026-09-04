"""Gateway configuration, read from the environment with usable defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

#: Tokens shipped for local development and the test-suite. Real deployments
#: override these via GATEWAY_TOKENS (or replace the resolver entirely -- see
#: `auth.TokenResolver`).
DEFAULT_TOKENS: dict[str, str] = {
    "admin-token": "admin",
    "viewer-token": "viewer",
}


def _parse_tokens(raw: str) -> dict[str, str]:
    """Parse `GATEWAY_TOKENS` in the form `token:role,token:role`."""
    tokens: dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair:
            continue
        token, _, role = pair.partition(":")
        if not token or not role:
            raise ValueError(f"malformed GATEWAY_TOKENS entry: {pair!r}")
        tokens[token.strip()] = role.strip().lower()
    return tokens


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    #: Base URL of the downstream MCP server.
    upstream_url: str = "http://127.0.0.1:9000/mcp"
    #: Tools whose name starts with this prefix require `admin_role`.
    admin_prefix: str = "admin_"
    admin_role: str = "admin"
    #: Bearer token -> role.
    tokens: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_TOKENS))
    #: When true, `tools/list` responses are stripped of admin-only tools for
    #: non-admin callers. Off by default: the brief asks for `tools/list` to be
    #: forwarded transparently.
    filter_tools_list: bool = False
    upstream_timeout_seconds: float = 30.0

    @classmethod
    def from_env(cls) -> "Settings":
        raw_tokens = os.getenv("GATEWAY_TOKENS")
        return cls(
            upstream_url=os.getenv("GATEWAY_UPSTREAM_URL", cls.upstream_url),
            admin_prefix=os.getenv("GATEWAY_ADMIN_PREFIX", cls.admin_prefix),
            admin_role=os.getenv("GATEWAY_ADMIN_ROLE", cls.admin_role).lower(),
            tokens=_parse_tokens(raw_tokens) if raw_tokens else dict(DEFAULT_TOKENS),
            filter_tools_list=_env_bool("GATEWAY_FILTER_TOOLS_LIST", False),
            upstream_timeout_seconds=float(
                os.getenv("GATEWAY_UPSTREAM_TIMEOUT", cls.upstream_timeout_seconds)
            ),
        )
