"""ASGI entrypoint: `uvicorn mcp_gateway.app:app`."""

from .gateway import create_app

app = create_app()
