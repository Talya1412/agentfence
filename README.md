# AgentFence

AgentFence is a local, provider-neutral MCP JSONL stdio proxy. It filters `tools/list`, evaluates `tools/call`, emits redacted JSONL audit records, and forwards only allowed calls.

## 60-second demo

```powershell
go build -trimpath -o dist/agentfence ./cmd/agentfence
Copy-Item agentfence.example.json agentfence.json
go run ./cmd/agentfence check -config agentfence.json
```

Run proxy against any line-oriented MCP server:

```powershell
dist\agentfence.exe proxy -config agentfence.json -audit audit.jsonl -server your-mcp-server
```

Use `dry-run` to return policy decisions without forwarding calls. `inspect` prints parsed config. `explain -tool NAME` explains current decision. Stdout stays JSONL protocol-clean; diagnostics go stderr. `tools/list` pagination currently fails closed when downstream returns `nextCursor`; proxy never exposes an incomplete inventory.

## Configuration

See `agentfence.example.json`. Defaults fail closed. Explicit tool decisions override defaults. JSON-RPC uses strict bounded newline frames, valid IDs, no trailing JSON, and no notification responses. Shell tools require object `argv` and reject operators/substitution. Paths require absolute component-aware roots. URL-like values require valid scheme and host allowlists. Result/error payloads are redacted and bounded.

## Development

```powershell
gofmt -w cmd internal
go test ./...
go test -race ./...
go vet ./...
go build -trimpath -o dist/agentfence ./cmd/agentfence
```

Module path is `github.com/agentfence/agentfence`, a neutral local module path with no external dependencies.

## Threat model and coverage

See `THREAT_MODEL.md`. AgentFence governs intercepted client messages only. It does not provide HTTP, OS sandboxing, DNS/network enforcement, parser-grade SQL checks, prompt-injection defense, symlink/TOCTOU protection, tamper-proof audit, or a process-tree kill guarantee. MCP references used for constraints: [transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports), [tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools), and [authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).
