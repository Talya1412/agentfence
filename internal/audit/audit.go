package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type Entry struct {
	Event       string      `json:"event"`
	Method      string      `json:"method,omitempty"`
	Tool        string      `json:"tool,omitempty"`
	Decision    string      `json:"decision,omitempty"`
	Reason      string      `json:"reason,omitempty"`
	Fingerprint string      `json:"fingerprint,omitempty"`
	Data        interface{} `json:"data,omitempty"`
}
type Redactor struct {
	keys     map[string]struct{}
	patterns []*regexp.Regexp
}

func NewRedactor(keys, patterns []string) (Redactor, error) {
	r := Redactor{keys: map[string]struct{}{}}
	for _, key := range keys {
		r.keys[strings.ToLower(key)] = struct{}{}
	}
	for _, pattern := range patterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return Redactor{}, fmt.Errorf("compile redaction pattern: %w", err)
		}
		r.patterns = append(r.patterns, compiled)
	}
	return r, nil
}
func (r Redactor) Apply(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		out := map[string]interface{}{}
		for key, child := range typed {
			if _, ok := r.keys[strings.ToLower(key)]; ok {
				out[key] = "[REDACTED]"
			} else {
				out[key] = r.Apply(child)
			}
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(typed))
		for i, child := range typed {
			out[i] = r.Apply(child)
		}
		return out
	case string:
		out := typed
		for _, pattern := range r.patterns {
			out = pattern.ReplaceAllString(out, "[REDACTED]")
		}
		return out
	default:
		return value
	}
}
func Fingerprint(value interface{}) string {
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func JSONLine(entry Entry) ([]byte, error) {
	data, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("marshal audit entry: %w", err)
	}
	return append(data, '\n'), nil
}
