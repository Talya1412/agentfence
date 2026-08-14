package policy

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/agentfence/agentfence/internal/config"
)

type Decision string

const (
	Allow           Decision = "allow"
	Deny            Decision = "deny"
	RequireApproval Decision = "require_approval"
)

type Result struct {
	Decision    Decision
	ReasonCode  string
	Explanation string
}
type Request struct {
	Name      string
	Arguments json.RawMessage
}

func Evaluate(cfg config.Config, req Request) Result {
	tool, explicit := cfg.Tools[req.Name]
	decision := cfg.Defaults.Decision
	if explicit {
		decision = tool.Decision
	}
	if decision == "deny" {
		return Result{Deny, "tool_denied", "tool is not permitted by policy"}
	}
	if decision == "require_approval" {
		return Result{RequireApproval, "approval_unavailable", "interactive approval is unavailable in non-interactive proxy mode"}
	}
	if len(req.Arguments) > cfg.Budgets.MaxInputBytes {
		return Result{Deny, "input_budget_exceeded", "tool arguments exceed configured byte budget"}
	}
	if reason := checkArguments(tool, cfg, req.Arguments); reason != "" {
		return Result{Deny, reason, explanation(reason)}
	}
	return Result{Allow, "allowed", "tool call matches policy"}
}

func checkArguments(tool config.Tool, cfg config.Config, raw json.RawMessage) string {
	var value interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		return "invalid_arguments"
	}
	if tool.Shell && !shellArgumentsAllowed(value) {
		return "shell_restricted"
	}
	if tool.DestructiveSQL && containsSQL(string(raw)) {
		return "destructive_sql_restricted"
	}
	if len(tool.Paths) > 0 && !pathsAllowed(value, tool.Paths) {
		return "path_not_allowed"
	}
	if len(tool.Hosts) > 0 || len(tool.Schemes) > 0 || len(cfg.Network.AllowedHosts) > 0 || len(cfg.Network.AllowedSchemes) > 0 {
		if !urlsAllowed(value, tool, cfg.Network) {
			return "url_not_allowed"
		}
	}
	return ""
}

func shellArgumentsAllowed(value interface{}) bool {
	object, ok := value.(map[string]interface{})
	if !ok {
		return false
	}
	argv, ok := object["argv"].([]interface{})
	if !ok || len(argv) == 0 {
		return false
	}
	for _, item := range argv {
		arg, ok := item.(string)
		if !ok || containsShell(arg) {
			return false
		}
	}
	return true
}

func containsShell(text string) bool {
	lower := strings.ToLower(text)
	for _, token := range []string{"&&", "||", ";", "|", ">", "<", "$(", "`", "../", "sudo ", " rm "} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func containsSQL(text string) bool {
	lower := strings.ToLower(text)
	for _, token := range []string{"drop table", "drop database", "truncate table", "delete from", "alter table"} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func pathsAllowed(value interface{}, allowed []string) bool {
	for _, root := range allowed {
		if !filepath.IsAbs(root) {
			return false
		}
	}
	for _, candidate := range stringsFrom(value) {
		path := filepath.Clean(candidate)
		matched := false
		for _, root := range allowed {
			root = filepath.Clean(root)
			if !filepath.IsAbs(root) || !filepath.IsAbs(path) {
				return false
			}
			rel, err := filepath.Rel(root, path)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				matched = true
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func stringsFrom(value interface{}) []string {
	var out []string
	switch typed := value.(type) {
	case string:
		out = append(out, typed)
	case []interface{}:
		for _, child := range typed {
			out = append(out, stringsFrom(child)...)
		}
	case map[string]interface{}:
		for _, child := range typed {
			out = append(out, stringsFrom(child)...)
		}
	}
	return out
}

func urlsAllowed(value interface{}, tool config.Tool, network config.Network) bool {
	schemes := restrictiveAllowlist(tool.Schemes, network.AllowedSchemes)
	hosts := restrictiveAllowlist(tool.Hosts, network.AllowedHosts)
	for _, candidate := range stringsFrom(value) {
		if !looksLikeURL(candidate) {
			continue
		}
		parsed, err := url.Parse(candidate)
		if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" || !contains(schemes, strings.ToLower(parsed.Scheme)) || !contains(hosts, strings.ToLower(parsed.Hostname())) {
			return false
		}
	}
	return true
}

func restrictiveAllowlist(tool, global []string) []string {
	if len(global) == 0 {
		return tool
	}
	if len(tool) == 0 {
		return global
	}
	intersection := make([]string, 0, len(tool))
	for _, candidate := range tool {
		if contains(global, candidate) {
			intersection = append(intersection, candidate)
		}
	}
	return intersection
}

func looksLikeURL(value string) bool {
	if strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	return strings.Contains(value, "://") || strings.HasPrefix(value, "//") || strings.HasPrefix(strings.ToLower(value), "http:") || strings.HasPrefix(strings.ToLower(value), "https:") || strings.Contains(value, ".")
}
func contains(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}
func explanation(reason string) string {
	switch reason {
	case "invalid_arguments":
		return "arguments must be valid JSON"
	case "shell_restricted":
		return "shell requires argv and rejects operators or substitution"
	case "destructive_sql_restricted":
		return "SQL contains a destructive statement"
	case "path_not_allowed":
		return "path falls outside configured absolute roots"
	case "url_not_allowed":
		return "URL scheme or host is outside configured allowlist"
	}
	return "request rejected by policy"
}
