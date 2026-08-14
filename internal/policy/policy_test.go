package policy

import (
	"encoding/json"
	"testing"

	"github.com/agentfence/agentfence/internal/config"
)

func TestEvaluate_deniesUnknownTool(t *testing.T) {
	cfg := config.Default()
	result := Evaluate(cfg, Request{Name: "unknown", Arguments: json.RawMessage(`{}`)})
	if result.Decision != Deny || result.ReasonCode != "tool_denied" {
		t.Fatalf("got %#v", result)
	}
}

func TestEvaluate_blocksShell(t *testing.T) {
	cfg := config.Default()
	cfg.Defaults.Decision = "allow"
	cfg.Tools["run"] = config.Tool{Decision: "allow", Shell: true}
	result := Evaluate(cfg, Request{Name: "run", Arguments: json.RawMessage(`{"command":"echo ok && rm -rf /"}`)})
	if result.Decision != Deny || result.ReasonCode != "shell_restricted" {
		t.Fatalf("got %#v", result)
	}
}
