# Contributing

Keep changes focused and standard-library-only unless dependency need is demonstrated. Do not add telemetry or claim controls absent from [THREAT_MODEL.md](THREAT_MODEL.md). Preserve stdout JSONL protocol cleanliness. Keep Go files cohesive and below 250 pure lines.

Before opening a change:

```powershell
gofmt -w cmd internal
go test ./...
go test -race ./...
go vet ./...
go build -trimpath -o dist/agentfence.exe ./cmd/agentfence
```

Use POSIX equivalents where needed: `gofmt -w cmd internal`, `go test ./...`, `go test -race ./...`, `go vet ./...`, and `go build -trimpath -o dist/agentfence ./cmd/agentfence`.

Policy changes need tests for decisions and proxy reachability. Documentation changes must keep commands executable and compatibility claims qualified. Never include secrets or generated binaries in a pull request.

See [SECURITY.md](SECURITY.md) for private reports and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community expectations.
