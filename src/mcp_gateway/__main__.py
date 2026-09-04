"""`python -m mcp_gateway` / `mcp-gateway` -- run the gateway, or the mock server."""

from __future__ import annotations

import argparse
import logging

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the MCP security gateway.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--mock-downstream",
        action="store_true",
        help="Run the mock MCP server instead of the gateway (default port 9000).",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    if args.mock_downstream:
        target = "mcp_gateway.downstream:app"
        port = 9000 if args.port == 8080 else args.port
    else:
        target = "mcp_gateway.app:app"
        port = args.port
    uvicorn.run(target, host=args.host, port=port)


if __name__ == "__main__":
    main()
