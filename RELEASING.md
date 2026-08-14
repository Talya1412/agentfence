# Local Release Artifacts

Repository release support is intentionally local and secret-free. No hosted upload, signing key, notarization credential, or package manager metadata is required.

PowerShell:

```powershell
$version = '0.1.0'
New-Item -ItemType Directory -Force "dist\release\$version" | Out-Null
go build -trimpath -o "dist\release\$version\agentfence-windows-amd64.exe" ./cmd/agentfence
go build -trimpath -o "dist\release\$version\fixture-mcp-windows-amd64.exe" ./cmd/fixture-mcp
Get-FileHash "dist\release\$version\agentfence-windows-amd64.exe" -Algorithm SHA256
```

POSIX shell:

```sh
version=0.1.0
mkdir -p "dist/release/$version"
GOOS=linux GOARCH=amd64 go build -trimpath -o "dist/release/$version/agentfence-linux-amd64" ./cmd/agentfence
GOOS=darwin GOARCH=arm64 go build -trimpath -o "dist/release/$version/agentfence-darwin-arm64" ./cmd/agentfence
sha256sum "dist/release/$version"/*
```

Run `go test ./...`, `go test -race ./...`, `go vet ./...`, and a fixture proxy smoke test before sharing artifacts. Record version and commit outside the binary. `-trimpath` removes local source paths; it does not sign or attest artifacts.
