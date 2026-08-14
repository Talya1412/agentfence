package audit

import "testing"

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
