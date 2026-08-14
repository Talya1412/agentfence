# Policy Cookbook

Examples use config fields implemented by AgentFence. Copy only fields relevant to your server and keep default deny.

## Allow one file-rooted tool

```json
{
  "defaults": {"decision": "deny"},
  "tools": {
    "read_file": {"decision": "allow", "paths": ["/srv/agent-data"]}
  }
}
```

Path checks are lexical and component-aware; configured entries act as absolute roots, not glob patterns. They do not resolve symlinks or prevent TOCTOU races.

## Allow one HTTPS host

```json
{
  "defaults": {"decision": "deny"},
  "tools": {
    "fetch": {"decision": "allow", "schemes": ["https"], "hosts": ["api.example.com"]}
  },
  "network": {"allowed_schemes": ["https"], "allowed_hosts": ["api.example.com"]}
}
```

This checks URL values in intercepted arguments. It does not enforce DNS, sockets, redirects, or downstream network behavior.

## Restrict shell-shaped arguments

```json
{
  "defaults": {"decision": "deny"},
  "tools": {
    "run": {"decision": "allow", "shell": true}
  }
}
```

Allowed calls need object `argv`. Selected shell operators, substitution, `../`, and `sudo ` or ` rm ` tokens are rejected lexically. This is not command parsing or execution isolation.

## Keep human approval closed

```json
{"tools": {"needs_human": {"decision": "require_approval"}}}
```

The current non-interactive CLI denies `require_approval` because no trusted approval channel exists.

## Redact audit and result values

```json
{
  "redaction": {
    "keys": ["password", "token", "secret", "api_key", "authorization"],
    "patterns": ["(?i)bearer [A-Za-z0-9._-]+"]
  }
}
```

Treat local audit files as sensitive. They are not tamper-proof; use filesystem permissions and retention controls outside AgentFence.
