package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/agentfence/agentfence/internal/audit"
	"github.com/agentfence/agentfence/internal/config"
	"github.com/agentfence/agentfence/internal/policy"
	"github.com/agentfence/agentfence/internal/proxy"
)

var (
	version = "dev"
	commit  = "unknown"
	built   = "unknown"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("command required: proxy, check, inspect, explain, dry-run, version; use --help")
	}
	if args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		_, err := fmt.Fprintln(stderr, "AgentFence: policy proxy for MCP JSONL stdio")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stderr, "commands: proxy, dry-run, check, inspect, explain, version")
		return err
	}
	switch args[0] {
	case "proxy":
		return runProxy(args[1:], stdin, stdout, stderr, false)
	case "dry-run":
		return runProxy(args[1:], stdin, stdout, stderr, true)
	case "check":
		return runCheck(args[1:], stdout)
	case "inspect":
		return runInspect(args[1:], stdout)
	case "explain":
		return runExplain(args[1:], stdout)
	case "version":
		return runVersion(args[1:], stdout)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
func load(path string) (config.Config, audit.Redactor, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return config.Config{}, audit.Redactor{}, err
	}
	redactor, err := audit.NewRedactor(cfg.Redaction.Keys, cfg.Redaction.Patterns)
	return cfg, redactor, err
}
func runProxy(args []string, stdin io.Reader, stdout, stderr io.Writer, dry bool) error {
	serverIndex := -1
	for index, arg := range args {
		if arg == "--server" {
			serverIndex = index
			break
		}
	}
	flagArgs := args
	var serverArgs []string
	if serverIndex >= 0 {
		if serverIndex+1 >= len(args) {
			return fmt.Errorf("--server requires a command")
		}
		flagArgs = args[:serverIndex+2]
		serverArgs = args[serverIndex+2:]
	}
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "agentfence.json", "config path")
	auditPath := fs.String("audit", "", "audit JSONL path")
	command := fs.String("server", "", "downstream command")
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	cfg, redactor, err := load(*configPath)
	if err != nil {
		return err
	}
	if dry {
		cfg.Mode = "dry-run"
	}
	if *command == "" {
		return fmt.Errorf("--server required")
	}
	if len(serverArgs) == 0 {
		serverArgs = fs.Args()
	}
	var auditWriter io.Writer
	var auditFile *os.File
	if *auditPath != "" {
		auditFile, err = os.OpenFile(*auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return fmt.Errorf("open audit: %w", err)
		}
		auditWriter = auditFile
		defer auditFile.Close()
	}
	timeout := time.Duration(cfg.Budgets.TimeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, *command, serverArgs...)
	downstreamIn, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	downstreamOut, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	proxyErr := proxy.Proxy{Config: cfg, Audit: auditWriter, Redactor: redactor}.Run(stdin, stdout, structReadWriter{Reader: downstreamIn, Writer: downstreamOut})
	if proxyErr != nil && cmd.Process != nil {
		if killErr := cmd.Process.Kill(); killErr != nil {
			return fmt.Errorf("proxy failed: %w; kill downstream: %v", proxyErr, killErr)
		}
	}
	if err := downstreamOut.Close(); proxyErr == nil && err != nil {
		proxyErr = fmt.Errorf("close downstream stdin: %w", err)
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		if proxyErr == nil {
			proxyErr = fmt.Errorf("downstream timeout after %s", timeout)
		}
	}
	if proxyErr == nil && waitErr != nil {
		return fmt.Errorf("downstream server: %w", waitErr)
	}
	return proxyErr
}

type structReadWriter struct {
	io.Reader
	io.Writer
}

func runCheck(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	path := fs.String("config", "agentfence.json", "config path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, _, err := load(*path)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, "valid", proxy.Inspect(cfg))
	return err
}
func runInspect(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	path := fs.String("config", "agentfence.json", "config path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, _, err := load(*path)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(data))
	return err
}
func runExplain(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	path := fs.String("config", "agentfence.json", "config path")
	name := fs.String("tool", "", "tool name")
	arguments := fs.String("arguments", "{}", "JSON object arguments")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, _, err := load(*path)
	if err != nil {
		return err
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(*arguments), &parsed); err != nil {
		return fmt.Errorf("invalid --arguments JSON object: %w", err)
	}
	if parsed == nil {
		return fmt.Errorf("invalid --arguments JSON object: expected object")
	}
	encoded, err := json.Marshal(parsed)
	if err != nil {
		return err
	}
	result := policy.Evaluate(cfg, policy.Request{Name: *name, Arguments: encoded})
	_, err = fmt.Fprintf(out, "%s: %s (%s)\n", result.Decision, result.Explanation, result.ReasonCode)
	return err
}

func runVersion(args []string, out io.Writer) error {
	if len(args) != 0 {
		return fmt.Errorf("version takes no arguments")
	}
	_, err := fmt.Fprintf(out, "agentfence %s commit=%s built=%s\n", version, commit, built)
	return err
}
