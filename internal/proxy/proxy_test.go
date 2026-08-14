package proxy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/agentfence/agentfence/internal/audit"
	"github.com/agentfence/agentfence/internal/config"
)

func TestRun_deniedCallNeverReachesDownstream(t *testing.T) {
	cfg := config.Default()
	var clientOut, downstream bytes.Buffer
	downstream.WriteString("")
	redactor, err := audit.NewRedactor(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"blocked","arguments":{}}}` + "\n"
	proxy := Proxy{Config: cfg, Redactor: redactor}
	if err := proxy.Run(strings.NewReader(request), &clientOut, &downstream); err != nil {
		t.Fatal(err)
	}
	if downstream.Len() != 0 {
		t.Fatalf("downstream received %q", downstream.String())
	}
	if !strings.Contains(clientOut.String(), "tool_denied") {
		t.Fatalf("response %q", clientOut.String())
	}
}

func TestRun_allowedCallReachesDownstream(t *testing.T) {
	cfg := config.Default()
	cfg.Tools["echo"] = config.Tool{Decision: "allow"}
	var clientOut, downstream bytes.Buffer
	response := map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": map[string]interface{}{"content": []interface{}{map[string]interface{}{"text": "ok"}}}}
	data, _ := json.Marshal(response)
	downstream.Write(data)
	downstream.WriteByte('\n')
	redactor, err := audit.NewRedactor(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}` + "\n"
	proxy := Proxy{Config: cfg, Redactor: redactor}
	if err := proxy.Run(strings.NewReader(request), &clientOut, &downstream); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(clientOut.String(), `"text":"ok"`) {
		t.Fatalf("response %q", clientOut.String())
	}
}

func TestRun_preservesNotifications(t *testing.T) {
	cfg := config.Default()
	var clientOut, downstream bytes.Buffer
	redactor, err := audit.NewRedactor(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"
	proxy := Proxy{Config: cfg, Redactor: redactor}
	if err := proxy.Run(strings.NewReader(request), &clientOut, &downstream); err != nil {
		t.Fatal(err)
	}
	if downstream.String() != request || clientOut.Len() != 0 {
		t.Fatalf("downstream=%q client=%q", downstream.String(), clientOut.String())
	}
}

func TestRun_deniedNotificationDropsWithoutResponse(t *testing.T) {
	cfg := config.Default()
	var clientOut, downstream bytes.Buffer
	redactor, err := audit.NewRedactor(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"blocked","arguments":{}}}` + "\n"
	if err := (Proxy{Config: cfg, Redactor: redactor}).Run(strings.NewReader(request), &clientOut, &downstream); err != nil {
		t.Fatal(err)
	}
	if clientOut.Len() != 0 || downstream.Len() != 0 {
		t.Fatalf("client=%q downstream=%q", clientOut.String(), downstream.String())
	}
}

func TestRun_rejectsWrongDownstreamResponseID(t *testing.T) {
	cfg := config.Default()
	cfg.Tools["echo"] = config.Tool{Decision: "allow"}
	redactor, err := audit.NewRedactor(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":2,"result":{}}` + "\n")
	var clientOut bytes.Buffer
	if err := (Proxy{Config: cfg, Redactor: redactor}).Run(strings.NewReader(request), &clientOut, downstream); err == nil {
		t.Fatal("accepted mismatched response ID")
	}
}

func TestRun_redactsErrorPayload(t *testing.T) {
	cfg := config.Default()
	cfg.Tools["echo"] = config.Tool{Decision: "allow"}
	redactor, err := audit.NewRedactor([]string{"secret"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"bad","data":{"secret":"value"}}}` + "\n")
	var clientOut bytes.Buffer
	if err := (Proxy{Config: cfg, Redactor: redactor}).Run(strings.NewReader(request), &clientOut, downstream); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(clientOut.String(), "value") || !strings.Contains(clientOut.String(), "[REDACTED]") {
		t.Fatalf("response=%q", clientOut.String())
	}
}

func TestRun_rejectsResultOverByteBudgetAfterRedaction(t *testing.T) {
	cfg := config.Default()
	cfg.Budgets.MaxResultBytes = 20
	cfg.Tools["echo"] = config.Tool{Decision: "allow"}
	redactor, err := audit.NewRedactor([]string{"secret"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"result":{"secret":"long-value-that-redacts"}}` + "\n")
	var clientOut bytes.Buffer
	err = (Proxy{Config: cfg, Redactor: redactor}).Run(strings.NewReader(request), &clientOut, downstream)
	if err == nil || !strings.Contains(err.Error(), "result exceeds configured byte budget") {
		t.Fatalf("err=%v", err)
	}
}

func TestRun_writesRedactedAuditEntry(t *testing.T) {
	cfg := config.Default()
	cfg.Tools["echo"] = config.Tool{Decision: "allow"}
	redactor, err := audit.NewRedactor([]string{"secret"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"secret":"value"}}}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"result":{}}` + "\n")
	var clientOut, auditOut bytes.Buffer
	err = (Proxy{Config: cfg, Audit: &auditOut, Redactor: redactor}).Run(strings.NewReader(request), &clientOut, downstream)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(auditOut.String(), "value") || !strings.Contains(auditOut.String(), "\"tool\":\"echo\"") {
		t.Fatalf("audit=%q", auditOut.String())
	}
}
