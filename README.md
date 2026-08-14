# AgentFence

[![CI](https://github.com/Talya1412/agentfence/actions/workflows/ci.yml/badge.svg)](https://github.com/Talya1412/agentfence/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

AgentFence sits between MCP client and downstream server:

```text
MCP client -> AgentFence -> downstream MCP server
                 |
          policy + redacted audit
```

It filters `tools/list`, evaluates `tools/call`, emits redacted JSONL audit records, and forwards allowed calls. It uses only the Go standard library.

AgentFence is an interception-layer policy tool. It is not an OS sandbox, network firewall, parser-backed SQL executor, prompt-injection defense, or process supervisor. Read [THREAT_MODEL.md](THREAT_MODEL.md) before relying on it.

## First run: local allow/deny demo

Requires Go 1.26 or newer. Commands below use repository files only. `cmd/fixture-mcp` is a small line-oriented downstream fixture; it is for local smoke testing, not production use.

PowerShell:

```powershell
New-Item -ItemType Directory -Force dist | Out-Null
go build -trimpath -o dist/agentfence.exe ./cmd/agentfence
go build -trimpath -o dist/fixture-mcp.exe ./cmd/fixture-mcp
Copy-Item agentfence.example.json agentfence.json
go run ./cmd/agentfence check -config agentfence.json
go run ./cmd/agentfence inspect -config agentfence.json
go run ./cmd/agentfence explain -config agentfence.json -tool read_file
go run ./cmd/agentfence explain -config agentfence.json -tool blocked
```

POSIX shell:

```sh
mkdir -p dist
go build -trimpath -o dist/agentfence ./cmd/agentfence
go build -trimpath -o dist/fixture-mcp ./cmd/fixture-mcp
cp agentfence.example.json agentfence.json
go run ./cmd/agentfence check -config agentfence.json
go run ./cmd/agentfence inspect -config agentfence.json
go run ./cmd/agentfence explain -config agentfence.json -tool read_file
go run ./cmd/agentfence explain -config agentfence.json -tool blocked
```

Run a complete fixture exchange. The fixture exposes `echo` and `blocked`. This demo config allows `echo` and keeps `blocked` denied, proving both successful forwarding and enforcement. Create `agentfence.demo.json`:

```json
{
  "version": 1,
  "mode": "enforce",
  "defaults": { "decision": "deny" },
  "tools": { "echo": { "decision": "allow" } },
  "budgets": { "max_input_bytes": 1048576, "max_result_bytes": 1048576, "max_lines": 100 }
}
```

Use `agentfence.demo.json` for commands below. Use POSIX shell for byte-oriented stdin, or send UTF-8 bytes from a PowerShell-compatible tool:

PowerShell with UTF-8 input:

```powershell
$requests = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}', '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}'
[IO.File]::WriteAllLines('requests.jsonl', $requests, [Text.UTF8Encoding]::new($false))
cmd /c ".\dist\agentfence.exe proxy -config agentfence.demo.json -audit audit.jsonl --server .\dist\fixture-mcp.exe < requests.jsonl"
Get-Content -Encoding utf8 audit.jsonl
Remove-Item requests.jsonl
```

POSIX shell:

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"blocked","arguments":{}}}' | ./dist/agentfence proxy -config agentfence.demo.json -audit audit.jsonl --server ./dist/fixture-mcp
cat audit.jsonl
```

Expected: `tools/list` contains `echo` but not `blocked`; `echo` returns a downstream result; `blocked` returns a policy denial and never reaches fixture. `check` validates config, `inspect` prints parsed config, `explain -tool NAME --arguments '{}'` prints the decision, and `version` identifies the binary. Stdout remains JSONL protocol output for proxy modes; diagnostics go to stderr.

For client integration, configure client to launch `agentfence proxy`; pass `--config` and `--server` as separate arguments. Client-specific JSON syntax varies, so verify with `tools/list` before enabling calls. Keep downstream diagnostics off stdout.

## Configuration and policy

Start from [agentfence.example.json](agentfence.example.json). Defaults deny. Explicit tool decisions override the default. Paths use absolute lexical roots. URL-like values require configured scheme and host allowlists. Shell policy expects object `argv` and rejects selected operators/substitution tokens. SQL checks are conservative lexical checks. Result/error data and audit values can be redacted and bounded by config.

See [POLICY_COOKBOOK.md](POLICY_COOKBOOK.md) for small policy patterns and [COMPATIBILITY.md](COMPATIBILITY.md) for supported transport and message expectations.

## Development

```powershell
gofmt -w cmd internal
go test ./...
go test -race ./...
go vet ./...
go build -trimpath -o dist/agentfence.exe ./cmd/agentfence
```

```sh
gofmt -w cmd internal
go test ./...
go test -race ./...
go vet ./...
go build -trimpath -o dist/agentfence ./cmd/agentfence
```

Local outputs under `dist/` are ignored. Tagged builds publish platform artifacts and `SHA256SUMS` through GitHub Releases when release workflow permissions are enabled. Artifacts are not currently signed or notarized. See [RELEASING.md](RELEASING.md).

## Scope and references

AgentFence governs intercepted newline-delimited JSON-RPC messages only. It bounds frames, results, errors, execution time, and `tools/list` pagination; validates supported portions of cached object input schemas; redacts configured keys and patterns; and writes local audit records. Out-of-band traffic, DNS resolution, socket egress, symlink/TOCTOU races, downstream side effects, descendant processes, and audit tampering remain outside this boundary.

See [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY.md](SECURITY.md). MCP references used for protocol constraints: [transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports), [tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools), and [authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization). MCP compatibility claims here are limited to observed JSONL stdio behavior and supported message shapes, not a universal MCP certification.
