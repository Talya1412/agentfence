package proxy

import (
	"bytes"
	"strings"
	"testing"

	"github.com/agentfence/agentfence/internal/audit"
	"github.com/agentfence/agentfence/internal/config"
)

func TestRun_rejectsMalformedToolsListResponse(t *testing.T) {
	cfg := config.Default()
	redactor, err := audit.NewRedactor(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"result":{"tools":"bad"}}` + "\n")
	var clientOut bytes.Buffer
	err = (Proxy{Config: cfg, Redactor: redactor}).Run(strings.NewReader(request), &clientOut, downstream)
	if err == nil || !strings.Contains(err.Error(), "decode tools/list response") {
		t.Fatalf("err=%v", err)
	}
}

func TestRun_rejectsToolWithoutInputSchema(t *testing.T) {
	cfg := config.Default()
	cfg.Defaults.Decision = "allow"
	redactor, err := audit.NewRedactor(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo"}]}}` + "\n")
	var clientOut bytes.Buffer
	err = (Proxy{Config: cfg, Redactor: redactor}).Run(strings.NewReader(request), &clientOut, downstream)
	if err == nil || !strings.Contains(err.Error(), "without object inputSchema") {
		t.Fatalf("err=%v", err)
	}
}

func TestRun_rejectsUnfilteredToolListPage(t *testing.T) {
	cfg := config.Default()
	cfg.Defaults.Decision = "allow"
	redactor, err := audit.NewRedactor(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"result":{"tools":[],"nextCursor":"page-2"}}` + "\n")
	var clientOut bytes.Buffer
	err = (Proxy{Config: cfg, Redactor: redactor}).Run(strings.NewReader(request), &clientOut, downstream)
	if err == nil || !strings.Contains(err.Error(), "pagination is unsupported") {
		t.Fatalf("err=%v", err)
	}
}

func TestRun_rejectsUnexpectedToolShapeWithoutPanic(t *testing.T) {
	cfg := config.Default()
	cfg.Defaults.Decision = "allow"
	redactor, err := audit.NewRedactor(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"result":{"tools":[null]}}` + "\n")
	var clientOut bytes.Buffer
	err = (Proxy{Config: cfg, Redactor: redactor}).Run(strings.NewReader(request), &clientOut, downstream)
	if err == nil || !strings.Contains(err.Error(), "without string name") {
		t.Fatalf("err=%v", err)
	}
}
