# Compatibility

Compatibility statements describe current repository behavior, not universal MCP certification.

| Area | Current support | Boundary |
| --- | --- | --- |
| Runtime | Go 1.26+; standard library only | Built and tested with repository Go toolchain |
| Transport | One downstream newline-delimited JSON-RPC stdio server | No HTTP or SSE transport |
| Proxy methods | `tools/list`, `tools/call`, and forwarding of other classified messages | Only intercepted messages are governed |
| `tools/list` | Bounded pagination, duplicate detection, supported primitive property-schema validation, filtering | Unsupported or nested object/array property schemas fail closed; pagination has configured limits; successful `tools/list` establishes the schema cache |
| `tools/call` | Object arguments, cached primitive schema checks, policy decision, bounded response | An explicitly allowed call without a cached schema is denied with `schema_unavailable` before downstream forwarding; downstream tool semantics and side effects are not modeled |
| Decisions | `allow`, `deny`, `require_approval`, plus `dry-run` mode | `require_approval` denies without trusted interactive channel |
| Client/server shape | Line-oriented JSON objects with valid JSON-RPC IDs | Malformed, oversized, or unsupported messages can fail closed |

## Provider and client guidance

Use a client/server integration that can launch a local stdio command and pass newline-delimited JSON-RPC. Configure the client to start AgentFence, then configure AgentFence `--server` for downstream command and arguments. Exact client configuration syntax varies by client and is not maintained here.

Do not infer support for HTTP, SSE, DNS enforcement, network isolation, OS sandboxing, prompt-injection defense, or approval UI from this matrix. Those are explicit non-claims in [THREAT_MODEL.md](THREAT_MODEL.md).
