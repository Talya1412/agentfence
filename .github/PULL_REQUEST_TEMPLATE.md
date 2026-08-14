## Change

Describe user-visible behavior or documentation impact.

## Validation

- [ ] `gofmt -w cmd internal` (if Go changed)
- [ ] `go test ./...`
- [ ] `go test -race ./...`
- [ ] `go vet ./...`
- [ ] `go build -trimpath -o dist/agentfence ./cmd/agentfence`
- [ ] Local fixture or matching documentation surface checked

## Safety and scope

- [ ] No runtime source or tests changed when task is documentation/workflow-only.
- [ ] No external dependencies or telemetry added.
- [ ] Claims match `THREAT_MODEL.md` and compatibility wording stays qualified.
- [ ] No secrets or generated binaries included.
