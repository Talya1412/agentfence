package config

import (
	"os"
	"strings"
	"testing"
)

func TestLoad_preservesDefaultsForValidPartialConfig(t *testing.T) {
	path := writeConfig(t, `{"version":1,"mode":"enforce","defaults":{"decision":"deny"}}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Budgets.MaxFrameBytes != Default().Budgets.MaxFrameBytes {
		t.Fatalf("max frame bytes = %d, want default %d", cfg.Budgets.MaxFrameBytes, Default().Budgets.MaxFrameBytes)
	}
}

func TestLoad_rejectsUnknownFields(t *testing.T) {
	path := writeConfig(t, `{"version":1,"mode":"enforce","defaults":{"decision":"deny"},"unexpected":true}`)

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "unknown field") || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("error = %v, want useful unknown-field error", err)
	}
}

func TestLoad_rejectsUnknownNestedFields(t *testing.T) {
	path := writeConfig(t, `{"version":1,"mode":"enforce","defaults":{"decision":"deny","unexpected":true}}`)

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "unknown field") || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("error = %v, want useful nested unknown-field error", err)
	}
}

func TestLoad_rejectsTrailingJSON(t *testing.T) {
	path := writeConfig(t, `{"version":1,"mode":"enforce","defaults":{"decision":"deny"}} {}`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("accepted trailing JSON")
	}
}

func TestLoad_rejectsRelativeToolPathRoot(t *testing.T) {
	path := writeConfig(t, `{"version":1,"mode":"enforce","defaults":{"decision":"deny"},"tools":{"read":{"decision":"allow","paths":["tmp"]}}}`)

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "path roots must be absolute") {
		t.Fatalf("error = %v, want absolute path validation", err)
	}
}

func TestLoad_rejectsInvalidRedactionPattern(t *testing.T) {
	path := writeConfig(t, `{"version":1,"mode":"enforce","defaults":{"decision":"deny"},"redaction":{"patterns":["["]}}`)

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "compile redaction pattern") {
		t.Fatalf("error = %v, want regex validation", err)
	}
}

func TestLoad_rejectsEmptyRedactionKey(t *testing.T) {
	path := writeConfig(t, `{"version":1,"mode":"enforce","defaults":{"decision":"deny"},"redaction":{"keys":[" "]}}`)

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "redaction keys must be nonempty") {
		t.Fatalf("error = %v, want key validation", err)
	}
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := t.TempDir() + string(os.PathSeparator) + "config.json"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
