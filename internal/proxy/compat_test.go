package proxy

import (
	"bytes"
	"strings"
	"testing"

	"github.com/agentfence/agentfence/internal/config"
)

func TestRun_acceptsToolCallsWithoutArguments(t *testing.T) {
	cfg := config.Default()
	cfg.Tools["echo"] = config.Tool{Decision: "allow"}
	requests := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo"}}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object","properties":{}}}]}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"result":{"content":[]}}` + "\n")
	var output bytes.Buffer
	if err := (Proxy{Config: cfg}).Run(strings.NewReader(requests), &output, downstream); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"id":2,"result":{"content":[]}`) {
		t.Fatalf("missing tool result: %s", output.String())
	}
}

func TestRun_forwardsToolListErrorAndKeepsSessionOpen(t *testing.T) {
	for _, page := range []string{"first", "later"} {
		t.Run(page, func(t *testing.T) {
			requests := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n" +
				`{"jsonrpc":"2.0","id":2,"method":"ping"}` + "\n"
			upstreamError := `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"list unavailable"}}` + "\n"
			if page == "later" {
				upstreamError = `{"jsonrpc":"2.0","id":1,"result":{"tools":[],"nextCursor":"next"}}` + "\n" +
					`{"jsonrpc":"2.0","id":"agentfence-list-2","error":{"code":-32603,"message":"list unavailable"}}` + "\n"
			}
			downstream := bytes.NewBufferString(upstreamError + `{"jsonrpc":"2.0","id":2,"result":{}}` + "\n")
			var output bytes.Buffer
			if err := (Proxy{Config: config.Default()}).Run(strings.NewReader(requests), &output, downstream); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), `"id":1,"error":{"code":-32603,"message":"list unavailable"}`) ||
				!strings.Contains(output.String(), `"id":2,"result":{}`) {
				t.Fatalf("expected original list error and subsequent ping result: %s", output.String())
			}
		})
	}
}
