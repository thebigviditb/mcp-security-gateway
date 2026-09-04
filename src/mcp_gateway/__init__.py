"""An authorizing reverse proxy for MCP servers spoken over HTTP/JSON-RPC."""

from .config import Settings
from .gateway import create_app

__all__ = ["Settings", "create_app"]
