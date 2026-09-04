"""Bearer-token extraction and role resolution."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    """The authenticated caller behind a request."""

    token: str
    role: str

    def has_role(self, role: str) -> bool:
        return self.role == role


class AuthError(Exception):
    """Raised when a request carries no usable credential.

    Transport-level authentication failures are surfaced as HTTP 401 with a
    `WWW-Authenticate` challenge (per the MCP authorization spec) rather than as
    a JSON-RPC error, because the failure is not tied to any single message in
    the payload.
    """

    def __init__(self, message: str, *, error: str = "invalid_token") -> None:
        super().__init__(message)
        self.message = message
        self.error = error


class TokenResolver:
    """Maps opaque bearer tokens to roles.

    A static map keeps the challenge self-contained. Swapping in JWT validation
    or an introspection endpoint means replacing `resolve` only -- the gateway
    depends on nothing else here.
    """

    def __init__(self, tokens: dict[str, str]) -> None:
        self._tokens = dict(tokens)

    def resolve(self, token: str) -> Principal:
        role = self._tokens.get(token)
        if role is None:
            raise AuthError("Unknown or expired bearer token")
        return Principal(token=token, role=role)


def parse_bearer(header_value: str | None) -> str:
    """Extract the token from an `Authorization: Bearer <token>` header."""
    if not header_value:
        raise AuthError("Missing Authorization header", error="missing_token")
    scheme, _, token = header_value.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise AuthError("Authorization header must use the Bearer scheme")
    return token.strip()


def authenticate(header_value: str | None, resolver: TokenResolver) -> Principal:
    return resolver.resolve(parse_bearer(header_value))
