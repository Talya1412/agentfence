package policy

import (
	"encoding/json"
	"testing"

	"github.com/agentfence/agentfence/internal/config"
)

func TestEvaluate_explicitDecisionOverridesDefault(t *testing.T) {
	cfg := config.Default()
	cfg.Defaults.Decision = "deny"
	cfg.Tools["safe"] = config.Tool{Decision: "allow"}
	if got := Evaluate(cfg, Request{Name: "safe", Arguments: json.RawMessage(`{}`)}); got.Decision != Allow {
		t.Fatalf("got %#v", got)
	}
}

func TestEvaluate_shellRequiresArgvAndRejectsSubstitution(t *testing.T) {
	cfg := config.Default()
	cfg.Defaults.Decision = "allow"
	cfg.Tools["run"] = config.Tool{Decision: "allow", Shell: true}
	for _, raw := range []string{`{"command":"echo ok"}`, `{"argv":["sh","-c","echo $(whoami)"]}`} {
		if got := Evaluate(cfg, Request{Name: "run", Arguments: json.RawMessage(raw)}); got.ReasonCode != "shell_restricted" {
			t.Fatalf("got %#v", got)
		}
	}
}

func TestEvaluate_pathsRequireAbsoluteComponentRoot(t *testing.T) {
	cfg := config.Default()
	cfg.Defaults.Decision = "allow"
	cfg.Tools["read"] = config.Tool{Decision: "allow", Paths: []string{"/safe/root"}}
	for _, raw := range []string{`{"path":"/safe/rooted/file"}`, `{"path":"relative/file"}`} {
		if got := Evaluate(cfg, Request{Name: "read", Arguments: json.RawMessage(raw)}); got.ReasonCode != "path_not_allowed" {
			t.Fatalf("got %#v", got)
		}
	}
}

func TestEvaluate_urlControlsFailClosed(t *testing.T) {
	cfg := config.Default()
	cfg.Defaults.Decision = "allow"
	cfg.Tools["fetch"] = config.Tool{Decision: "allow", Schemes: []string{"https"}, Hosts: []string{"example.com"}}
	for _, raw := range []string{`{"url":"example.com/path"}`, `{"url":"https://evil.example/path"}`} {
		if got := Evaluate(cfg, Request{Name: "fetch", Arguments: json.RawMessage(raw)}); got.ReasonCode != "url_not_allowed" {
			t.Fatalf("got %#v", got)
		}
	}
}

func TestEvaluate_approvalFailsClosedWithoutTrustedChannel(t *testing.T) {
	cfg := config.Default()
	cfg.Tools["sensitive"] = config.Tool{Decision: "require_approval"}
	got := Evaluate(cfg, Request{Name: "sensitive", Arguments: json.RawMessage(`{}`)})
	if got.Decision != RequireApproval || got.ReasonCode != "approval_unavailable" {
		t.Fatalf("got %#v", got)
	}
}

func TestEvaluate_inputBudgetRejectsBeforeArgumentPolicy(t *testing.T) {
	cfg := config.Default()
	cfg.Budgets.MaxInputBytes = 4
	cfg.Defaults.Decision = "allow"
	cfg.Tools["echo"] = config.Tool{Decision: "allow"}
	got := Evaluate(cfg, Request{Name: "echo", Arguments: json.RawMessage(`{"x":1}`)})
	if got.Decision != Deny || got.ReasonCode != "input_budget_exceeded" {
		t.Fatalf("got %#v", got)
	}
}
