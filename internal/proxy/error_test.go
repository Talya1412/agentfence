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

func TestRun_rejectsUnsupportedSchemaKeyword(t *testing.T) {
	cfg := config.Default()
	cfg.Defaults.Decision = "allow"
	redactor, err := audit.NewRedactor(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object","properties":{"value":{"type":"string","minLength":1}}}}]}}` + "\n")
	var clientOut bytes.Buffer
	err = (Proxy{Config: cfg, Redactor: redactor}).Run(strings.NewReader(request), &clientOut, downstream)
	if err == nil || !strings.Contains(err.Error(), `unsupported keyword "minLength"`) {
		t.Fatalf("err=%v", err)
	}
}

func TestRun_rejectsUnsupportedNestedSchemaStructure(t *testing.T) {
	cfg := config.Default()
	cfg.Defaults.Decision = "allow"
	redactor, err := audit.NewRedactor(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object","properties":{"value":{"type":"array","items":{"type":"string"}}}}}]}}` + "\n")
	var clientOut bytes.Buffer
	err = (Proxy{Config: cfg, Redactor: redactor}).Run(strings.NewReader(request), &clientOut, downstream)
	if err == nil || !strings.Contains(err.Error(), `unsupported keyword "items"`) {
		t.Fatalf("err=%v", err)
	}
}

func TestRun_aggregatesToolListPages(t *testing.T) {
	cfg := config.Default()
	cfg.Defaults.Decision = "allow"
	redactor, err := audit.NewRedactor(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"one","inputSchema":{"type":"object"}}],"nextCursor":"page-2"}}` + "\n" + `{"jsonrpc":"2.0","id":"agentfence-list-2","result":{"tools":[{"name":"two","inputSchema":{"type":"object"}}]}}` + "\n")
	var clientOut bytes.Buffer
	err = (Proxy{Config: cfg, Redactor: redactor}).Run(strings.NewReader(request), &clientOut, downstream)
	if err != nil || !strings.Contains(clientOut.String(), `"name":"one"`) || !strings.Contains(clientOut.String(), `"name":"two"`) {
		t.Fatalf("err=%v response=%s", err, clientOut.String())
	}
}

func TestRun_rejectsCursorCycle(t *testing.T) {
	cfg := config.Default()
	cfg.Defaults.Decision = "allow"
	redactor, _ := audit.NewRedactor(nil, nil)
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"result":{"tools":[],"nextCursor":"same"}}` + "\n" + `{"jsonrpc":"2.0","id":"agentfence-list-2","result":{"tools":[],"nextCursor":"same"}}` + "\n")
	var clientOut bytes.Buffer
	err := (Proxy{Config: cfg, Redactor: redactor}).Run(strings.NewReader(request), &clientOut, downstream)
	if err == nil || !strings.Contains(err.Error(), "cursor cycle") {
		t.Fatalf("err=%v", err)
	}
}

func TestRun_rejectsSchemaBypass(t *testing.T) {
	cfg := config.Default()
	cfg.Tools["echo"] = config.Tool{Decision: "allow"}
	redactor, _ := audit.NewRedactor(nil, nil)
	requests := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"value":1}}}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object","properties":{"value":{"type":"string"}},"additionalProperties":false}}]}}` + "\n")
	var clientOut bytes.Buffer
	err := (Proxy{Config: cfg, Redactor: redactor}).Run(strings.NewReader(requests), &clientOut, downstream)
	if err != nil || !strings.Contains(clientOut.String(), "schema_validation_failed") || strings.Contains(downstream.String(), `"id":2`) {
		t.Fatalf("err=%v client=%s downstream=%s", err, clientOut.String(), downstream.String())
	}
}

func TestRun_validatesCallAgainstRawSchemaAfterListRedaction(t *testing.T) {
	cfg := config.Default()
	cfg.Tools["echo"] = config.Tool{Decision: "allow"}
	redactor, err := audit.NewRedactor([]string{"secret"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	requests := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"secret":"value"}}}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object","properties":{"secret":{"type":"string"}},"additionalProperties":false}}]}}` + "\n" + `{"jsonrpc":"2.0","id":2,"result":{}}` + "\n")
	var clientOut bytes.Buffer
	err = (Proxy{Config: cfg, Redactor: redactor}).Run(strings.NewReader(requests), &clientOut, downstream)
	if err != nil || !strings.Contains(downstream.String(), `"id":2`) || strings.Contains(clientOut.String(), "schema_validation_failed") {
		t.Fatalf("err=%v client=%s downstream=%s", err, clientOut.String(), downstream.String())
	}
}

func TestRun_rejectsSinglePageToolsListOverByteBudget(t *testing.T) {
	cfg := config.Default()
	cfg.Budgets.MaxListBytes = 10
	redactor, err := audit.NewRedactor(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}` + "\n")
	var clientOut bytes.Buffer
	err = (Proxy{Config: cfg, Redactor: redactor}).Run(strings.NewReader(request), &clientOut, downstream)
	if err == nil || !strings.Contains(err.Error(), "tools/list aggregate exceeds byte budget") {
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

func TestRun_rejectsMismatchedDownstreamResponse(t *testing.T) {
	cfg := config.Default()
	cfg.Defaults.Decision = "allow"
	redactor, err := audit.NewRedactor(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":2,"result":{}}` + "\n")
	var clientOut bytes.Buffer
	err = (Proxy{Config: cfg, Redactor: redactor}).Run(strings.NewReader(request), &clientOut, downstream)
	if err == nil || !strings.Contains(err.Error(), "response id does not match") {
		t.Fatalf("err=%v", err)
	}
	if clientOut.Len() != 0 {
		t.Fatalf("forwarded mismatched response: %s", clientOut.String())
	}
}

func TestRun_rejectsDownstreamRequestAsResponse(t *testing.T) {
	cfg := config.Default()
	redactor, err := audit.NewRedactor(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"unexpected"}` + "\n")
	var clientOut bytes.Buffer
	err = (Proxy{Config: cfg, Redactor: redactor}).Run(strings.NewReader(request), &clientOut, downstream)
	if err == nil || !strings.Contains(err.Error(), "not a response") {
		t.Fatalf("err=%v", err)
	}
	if clientOut.Len() != 0 {
		t.Fatalf("forwarded downstream request: %s", clientOut.String())
	}
}
