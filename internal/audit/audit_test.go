package audit

import (
	"strings"
	"testing"
)

func TestRedactor_recursesKeysAndPatterns(t *testing.T) {
	r, err := NewRedactor([]string{"token"}, []string{"secret-[0-9]+"})
	if err != nil {
		t.Fatal(err)
	}
	got := r.Apply(map[string]interface{}{"token": "value", "nested": []interface{}{"secret-42"}}).(map[string]interface{})
	if got["token"] != "[REDACTED]" || got["nested"].([]interface{})[0] != "[REDACTED]" {
		t.Fatalf("got %#v", got)
	}
}

func TestFingerprint_normalizesObjectKeyOrder(t *testing.T) {
	first := map[string]interface{}{"b": "two", "a": "one"}
	second := map[string]interface{}{"a": "one", "b": "two"}

	if Fingerprint(first) != Fingerprint(second) {
		t.Fatal("fingerprints differ for equivalent JSON objects")
	}
	if len(Fingerprint(first)) != 64 {
		t.Fatalf("fingerprint length = %d, want 64", len(Fingerprint(first)))
	}
}

func TestJSONLine_doesNotIncludeArgumentValuesWhenEntryHasFingerprintOnly(t *testing.T) {
	line, err := JSONLine(Entry{Event: "tool_call", Fingerprint: Fingerprint(map[string]interface{}{"secret": "value"})})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(line), "value") || strings.Contains(string(line), "secret") {
		t.Fatalf("audit line discloses arguments: %s", line)
	}
}
