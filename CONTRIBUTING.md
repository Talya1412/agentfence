# Contributing

Use standard-library-only Go changes unless dependency need is demonstrated. Keep files cohesive and below 250 pure lines. Preserve stdout JSONL protocol cleanliness. Add tests for policy decisions and proxy reachability. Run `gofmt`, `go test ./...`, `go test -race ./...`, `go vet ./...`, and the documented build before submitting.
