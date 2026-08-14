package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Config struct {
	Version   int             `json:"version"`
	Mode      string          `json:"mode"`
	Defaults  Defaults        `json:"defaults"`
	Tools     map[string]Tool `json:"tools"`
	Network   Network         `json:"network"`
	Budgets   Budgets         `json:"budgets"`
	Redaction Redaction       `json:"redaction"`
}

type Defaults struct {
	Decision string `json:"decision"`
}
type Tool struct {
	Decision       string   `json:"decision"`
	Paths          []string `json:"paths"`
	Hosts          []string `json:"hosts"`
	Schemes        []string `json:"schemes"`
	Shell          bool     `json:"shell"`
	DestructiveSQL bool     `json:"destructive_sql"`
}
type Network struct {
	AllowedSchemes []string `json:"allowed_schemes"`
	AllowedHosts   []string `json:"allowed_hosts"`
}
type Budgets struct {
	MaxInputBytes  int `json:"max_input_bytes"`
	MaxResultBytes int `json:"max_result_bytes"`
	MaxListBytes   int `json:"max_list_bytes"`
	MaxListPages   int `json:"max_list_pages"`
	MaxLines       int `json:"max_lines"`
	MaxFrameBytes  int `json:"max_frame_bytes"`
	TimeoutSeconds int `json:"timeout_seconds"`
}
type Redaction struct {
	Keys     []string `json:"keys"`
	Patterns []string `json:"patterns"`
}

func Default() Config {
	return Config{Version: 1, Mode: "enforce", Defaults: Defaults{Decision: "deny"}, Tools: map[string]Tool{}, Budgets: Budgets{MaxInputBytes: 64 * 1024, MaxResultBytes: 256 * 1024, MaxListBytes: 1024 * 1024, MaxListPages: 32, MaxLines: 1000, MaxFrameBytes: 1024 * 1024, TimeoutSeconds: 30}, Redaction: Redaction{Keys: []string{"password", "token", "secret", "api_key", "authorization"}}}
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	cfg := Default()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return Config{}, fmt.Errorf("parse config: trailing JSON data")
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("config version must be 1")
	}
	if c.Mode != "enforce" && c.Mode != "dry-run" {
		return fmt.Errorf("mode must be enforce or dry-run")
	}
	if !validDecision(c.Defaults.Decision) {
		return fmt.Errorf("invalid default decision")
	}
	if c.Budgets.MaxInputBytes <= 0 || c.Budgets.MaxResultBytes <= 0 || c.Budgets.MaxListBytes <= 0 || c.Budgets.MaxListPages <= 0 || c.Budgets.MaxLines <= 0 || c.Budgets.MaxFrameBytes <= 0 || c.Budgets.TimeoutSeconds <= 0 {
		return fmt.Errorf("budgets must be positive")
	}
	for name, tool := range c.Tools {
		if name == "" || !validDecision(tool.Decision) {
			return fmt.Errorf("invalid tool policy for %q", name)
		}
		for _, root := range tool.Paths {
			if strings.TrimSpace(root) == "" || !filepath.IsAbs(root) {
				return fmt.Errorf("tool %q path roots must be absolute", name)
			}
		}
	}
	for _, key := range c.Redaction.Keys {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("redaction keys must be nonempty")
		}
	}
	for _, pattern := range c.Redaction.Patterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("compile redaction pattern: %w", err)
		}
	}
	return nil
}

func validDecision(value string) bool {
	return value == "allow" || value == "deny" || value == "require_approval"
}
