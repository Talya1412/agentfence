package main

import (
	"bytes"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestRunProxy_forwardsServerArgumentsAndClosesLifecycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell argument fixture differs on Windows")
	}
	configPath := t.TempDir() + "/config.json"
	configJSON := `{"version":1,"mode":"enforce","defaults":{"decision":"deny"},"tools":{"echo":{"decision":"allow"}},"budgets":{"max_input_bytes":1024,"max_result_bytes":1024,"max_lines":10}}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0600); err != nil {
		t.Fatal(err)
	}
	serverPath := t.TempDir() + "/server.sh"
	serverScript := "#!/bin/sh\nprintf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"echo\",\"inputSchema\":{\"type\":\"object\"}}]}}'\nprintf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"arg\":\"'$1'\"}}'\n"
	if err := os.WriteFile(serverPath, []byte(serverScript), 0700); err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}` + "\n"
	var stdout, stderr bytes.Buffer
	err := run([]string{"proxy", "--config", configPath, "--server", "sh", serverPath, "forwarded"}, strings.NewReader(request), &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"arg":"forwarded"`) {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestRun_help(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"--help"}, strings.NewReader(""), &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut.String(), "commands:") || out.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", out.String(), errOut.String())
	}
}

func TestRun_version(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"version"}, strings.NewReader(""), &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "agentfence dev") || errOut.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", out.String(), errOut.String())
	}
}
