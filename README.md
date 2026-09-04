# MCP Security Gateway

A lightweight HTTP/JSON-RPC reverse proxy that sits between an AI agent and a
downstream MCP server and enforces **role-based, tool-level authorization**.

```
  agent client ──Bearer <token>──▶  gateway  ──▶  downstream MCP server
                                      │
                                      └── -32001 Unauthorized Tool Call
                                          (downstream never sees the request)
```

The gateway is deliberately thin. It authenticates the caller, understands just
enough of the JSON-RPC envelope to route and authorize, and relays everything
else byte-for-byte. Anything it cannot evaluate is left to the downstream
server, which owns the actual tool semantics.

## Rules

| Incoming message | Behaviour |
| --- | --- |
| `tools/list` | forwarded transparently, for every role |
| `tools/call` with `params.name` starting `admin_` | requires the `admin` role, else intercepted |
| any other `tools/call` | forwarded |
| `initialize`, notifications, unknown methods | forwarded |
| no / unusable `Authorization: Bearer` header | `401` with a `WWW-Authenticate` challenge |

A denied call is answered by the gateway itself and **never reaches the
downstream server**:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "error": {
    "code": -32001,
    "message": "Unauthorized Tool Call",
    "data": {
      "reason": "Tool 'admin_reset_key' requires the 'admin' role; token has 'viewer'",
      "tool": "admin_reset_key"
    }
  }
}
```

## Quick start

```bash
uv venv && uv pip install -e ".[dev]"     # or: python -m venv .venv && pip install -e ".[dev]"

python -m mcp_gateway --mock-downstream    # mock MCP server on :9000
python -m mcp_gateway                      # gateway on :8080
```

```bash
# viewer sees the full catalogue -- tools/list is forwarded transparently
curl -s localhost:8080/mcp -H 'Authorization: Bearer viewer-token' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# viewer is blocked from an admin tool
curl -s localhost:8080/mcp -H 'Authorization: Bearer viewer-token' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call",
       "params":{"name":"admin_reset_key","arguments":{"tenant":"acme"}}}'

# admin is allowed through
curl -s localhost:8080/mcp -H 'Authorization: Bearer admin-token' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call",
       "params":{"name":"admin_reset_key","arguments":{"tenant":"acme"}}}'
```

Dev tokens: `admin-token` → `admin`, `viewer-token` → `viewer`.

## Tests

```bash
pytest            # 37 tests: auth, forwarding, policy, malformed wire format, batches
```

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `GATEWAY_UPSTREAM_URL` | `http://127.0.0.1:9000/mcp` | downstream MCP endpoint |
| `GATEWAY_TOKENS` | `admin-token:admin,viewer-token:viewer` | `token:role` pairs |
| `GATEWAY_ADMIN_PREFIX` | `admin_` | prefix that marks a privileged tool |
| `GATEWAY_ADMIN_ROLE` | `admin` | role required by that prefix |
| `GATEWAY_FILTER_TOOLS_LIST` | `false` | also strip admin tools from `tools/list` results |
| `GATEWAY_UPSTREAM_TIMEOUT` | `30` | seconds |

## Layout

| File | Role |
| --- | --- |
| [jsonrpc.py](src/mcp_gateway/jsonrpc.py) | JSON-RPC 2.0 envelope parsing and error construction |
| [auth.py](src/mcp_gateway/auth.py) | `Bearer` extraction, token → role resolution |
| [policy.py](src/mcp_gateway/policy.py) | the authorization rules, isolated and side-effect free |
| [gateway.py](src/mcp_gateway/gateway.py) | the proxy: middleware, forwarding, response merging |
| [downstream.py](src/mcp_gateway/downstream.py) | mock MCP server used for local runs and tests |

## Design notes

**Errors go where the client expects them.** A missing or unknown token is a
transport failure that belongs to no single message, so it returns HTTP 401 with
a `WWW-Authenticate` challenge, per the MCP authorization spec. Everything else
is a JSON-RPC-level failure and returns HTTP 200 with the error in the envelope,
carrying the original request `id` so the client can correlate it.

**Batches are partitioned, not rejected.** A batch containing one forbidden call
is split: the permitted messages go upstream, the denied ones are answered
locally, and the two sets are spliced back together by `id`. A batch in which
nothing survives policy never opens a connection at all.

**Transparent when it can be.** If no message was intercepted and no result
needs filtering, the original bytes are relayed unchanged and the response is
streamed straight back, so SSE responses and session affinity
(`Mcp-Session-Id`) keep working. The gateway only re-serializes when it actually
has something to merge. `GET` and `DELETE /mcp` are proxied too, so the full
Streamable HTTP surface works.

**The caller's token stops at the gateway.** Hop-by-hop headers are stripped per
RFC 9110 and the client `Authorization` header is dropped; the downstream server
receives the resolved identity as `X-MCP-Gateway-Role` instead.

**Fail closed.** A token with an unrecognised role is not an admin. Only an
exact prefix match gates a tool, so `administer_users` is not mistaken for a
privileged one -- and a `tools/call` the gateway cannot evaluate (no usable
`params.name`) is forwarded to the downstream server, which rejects it with
`-32602` rather than having the gateway guess.

**Notifications are respected.** A denied notification is dropped without a
response, because JSON-RPC forbids replying to one.

## Extending

`TokenResolver.resolve` is the only place that knows how a token becomes a role
— swap it for JWT verification or an introspection call and nothing else moves.
`ToolPolicy` holds the rules and has no I/O, so richer policies (per-tool
allowlists, argument inspection, rate limits) slot in without touching the
proxy.
