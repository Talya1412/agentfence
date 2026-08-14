# Threat Model and Coverage

## Protected boundary

AgentFence sits between an MCP client and one downstream JSONL stdio server. It can deny intercepted `tools/call` requests, filter advertised tools, redact returned JSON, and write local audit records.

## Covered threats

- Unknown tools denied by default.
- Explicit tool policy checks for paths, URL scheme/host, shell metacharacters, destructive SQL tokens, and input size.
- Approval requests denied when no trusted human approval channel exists.
- Sensitive configured keys and literal regex patterns redacted before audit and tool result output.
- Audit metadata can include SHA-256 fingerprints supplied by callers.

## Gaps and non-claims

- No OS sandbox, syscall restriction, network firewall, cloud control plane, telemetry, or arbitrary process enforcement.
- Symlink and TOCTOU attacks are not resolved by lexical path checks.
- Shell and SQL checks are lexical and conservative, not parsers.
- Structured shell argument semantics and downstream side effects are not fully modeled.
- Only newline-delimited JSON-RPC messages passing through proxy are governed; out-of-band traffic is not.
- Local audit files are not tamper-proof and require filesystem permissions.
- No HTTP/SSE transport, DNS/network enforcement, or OS sandbox.
- SQL detection remains lexical; no parser-grade SQL semantics.
- Symlink/TOCTOU races and process-tree termination are not guaranteed.
- No claim of universal prompt-injection defense.

## Remediation Matrix

| Limitation | Classification | Current evidence / behavior | Next remediation |
| --- | --- | --- | --- |
| JSONL frame exhaustion | Fixed | `ReadLimit` reads bounded chunks and rejects oversized frames before completion; regression test covers unterminated input. | Keep fuzzing frame boundaries. |
| Fractional JSON-RPC IDs | Fixed | IDs accept strings and integers only; fractional, null, and object IDs reject. | Add schema-generated protocol corpus if dependency policy changes. |
| Invalid `tools/list` tool shape | Fixed | Missing/non-object `inputSchema` and missing names fail closed. | Validate full MCP tool schema when schema validator is in scope. |
| `tools/list` pagination | Deferred, fail-closed | `nextCursor` is rejected instead of silently exposing incomplete inventory. | Add internal downstream request-ID allocator and page aggregation. |
| Human approval | Deferred by scope | `require_approval` denies because stdio CLI has no trusted UI/channel. | Add explicit approval adapter with authenticated caller, timeout, denial default, and audit binding. |
| Tool input JSON Schema validation | Deferred | Proxy validates call envelope and policy-specific fields, not arbitrary server schemas. | Validate cached `inputSchema` before forwarding calls. |
| Path symlink/TOCTOU | Platform limit | Lexical absolute component checks only. | Enforce canonical handles or OS sandbox at execution boundary. |
| Network/DNS enforcement | Platform limit | URL policy checks message values, not socket resolution or egress. | Move execution into network-isolated worker/sandbox. |
| Shell/SQL semantics | Deferred | Conservative lexical checks; no parser or execution isolation. | Use structured executors and parser-backed SQL policy. |
| Process-tree termination | Platform limit | `CommandContext` and direct process kill; descendants are not guaranteed. | Use OS job objects/process groups or sandbox supervisor. |
| Audit tamper resistance | Platform limit | Append-only local file with restrictive mode; no authenticated sink. | Add authenticated remote/WORM sink and key management. |
| Prompt injection | Impossible at proxy layer | Proxy can redact and enforce message policy, not determine model intent. | Apply upstream model/UI trust controls and human confirmation. |
