package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/agentfence/agentfence/internal/audit"
	"github.com/agentfence/agentfence/internal/config"
)

type shortWriter struct{}

func (shortWriter) Write(data []byte) (int, error) {
	return len(data) - 1, nil
}

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

func TestRun_malformedCallArgumentsPreserveInvalidParamsPath(t *testing.T) {
	cfg := config.Default()
	redactor, err := audit.NewRedactor(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"blocked","arguments":[]}}` + "\n"
	var clientOut, auditOut, downstream bytes.Buffer
	if err := (Proxy{Config: cfg, Audit: &auditOut, Redactor: redactor}).Run(strings.NewReader(request), &clientOut, &downstream); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(clientOut.String(), `"invalid_params"`) {
		t.Fatalf("response=%q", clientOut.String())
	}
	if auditOut.Len() != 0 || downstream.Len() != 0 {
		t.Fatalf("audit=%q downstream=%q", auditOut.String(), downstream.String())
	}
}

func TestRun_allowedCallReachesDownstream(t *testing.T) {
	cfg := config.Default()
	cfg.Tools["echo"] = config.Tool{Decision: "allow"}
	var clientOut, downstream bytes.Buffer
	listResponse := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object","properties":{}}}]}}` + "\n"
	response := map[string]interface{}{"jsonrpc": "2.0", "id": 2, "result": map[string]interface{}{"content": []interface{}{map[string]interface{}{"text": "ok"}}}}
	data, _ := json.Marshal(response)
	downstream.WriteString(listResponse)
	downstream.Write(data)
	downstream.WriteByte('\n')
	redactor, err := audit.NewRedactor(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}` + "\n"
	proxy := Proxy{Config: cfg, Redactor: redactor}
	if err := proxy.Run(strings.NewReader(request), &clientOut, &downstream); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(clientOut.String(), `"text":"ok"`) {
		t.Fatalf("response %q", clientOut.String())
	}
}

func TestRun_explicitlyAllowedCallWithoutSchemaIsDeniedBeforeForwarding(t *testing.T) {
	cfg := config.Default()
	cfg.Tools["echo"] = config.Tool{Decision: "allow"}
	redactor, err := audit.NewRedactor(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}` + "\n"
	var clientOut, downstream bytes.Buffer
	if err := (Proxy{Config: cfg, Redactor: redactor}).Run(strings.NewReader(request), &clientOut, &downstream); err != nil {
		t.Fatal(err)
	}
	if downstream.Len() != 0 {
		t.Fatalf("downstream received %q", downstream.String())
	}
	if !strings.Contains(clientOut.String(), "schema_unavailable") {
		t.Fatalf("response %q", clientOut.String())
	}
}

func TestValidateSchema_rejectsNestedObjectAndArrayProperties(t *testing.T) {
	tests := []struct {
		name         string
		propertyType string
	}{
		{name: "object", propertyType: "object"},
		{name: "array", propertyType: "array"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schema := map[string]json.RawMessage{
				"type":       json.RawMessage(`"object"`),
				"properties": json.RawMessage(`{"value":{"type":"` + test.propertyType + `"}}`),
			}
			if err := validateSchema(schema); err == nil || !strings.Contains(err.Error(), "nested "+test.propertyType+" property schemas are unsupported") {
				t.Fatalf("validateSchema() error = %v", err)
			}
		})
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
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object","properties":{}}}]}}` + "\n" + `{"jsonrpc":"2.0","id":3,"result":{}}` + "\n")
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
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object","properties":{}}}]}}` + "\n" + `{"jsonrpc":"2.0","id":2,"error":{"code":-1,"message":"bad","data":{"secret":"value"}}}` + "\n")
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
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object","properties":{}}}]}}` + "\n" + `{"jsonrpc":"2.0","id":2,"result":{"secret":"long-value-that-redacts"}}` + "\n")
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
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"secret":"value"}}}` + "\n"
	downstream := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object","properties":{"secret":{"type":"string"}}}}]}}` + "\n" + `{"jsonrpc":"2.0","id":2,"result":{}}` + "\n")
	var clientOut, auditOut bytes.Buffer
	err = (Proxy{Config: cfg, Audit: &auditOut, Redactor: redactor}).Run(strings.NewReader(request), &clientOut, downstream)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(auditOut.String(), "value") || strings.Contains(auditOut.String(), "secret") || !strings.Contains(auditOut.String(), "\"tool\":\"echo\"") || !strings.Contains(auditOut.String(), "\"fingerprint\":\"") {
		t.Fatalf("audit=%q", auditOut.String())
	}
}

func TestRun_writesStableArgumentFingerprintForEquivalentJSON(t *testing.T) {
	cfg := config.Default()
	redactor, err := audit.NewRedactor(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"blocked","arguments":{"b":2,"a":1}}}` + "\n",
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"blocked","arguments":{"a":1,"b":2}}}` + "\n",
	}
	var auditOut bytes.Buffer
	if err := (Proxy{Config: cfg, Audit: &auditOut, Redactor: redactor}).Run(strings.NewReader(requests[0]+requests[1]), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(auditOut.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit lines = %d, want 2: %q", len(lines), auditOut.String())
	}
	var first, second audit.Entry
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint == "" || first.Fingerprint != second.Fingerprint {
		t.Fatalf("fingerprints = %q, %q", first.Fingerprint, second.Fingerprint)
	}
}

func TestWriteAudit_rejectsShortWrite(t *testing.T) {
	proxy := Proxy{Audit: shortWriter{}}

	err := proxy.writeAudit(audit.Entry{Event: "tool_call"})
	if err != io.ErrShortWrite {
		t.Fatalf("writeAudit() error = %v, want %v", err, io.ErrShortWrite)
	}
}
