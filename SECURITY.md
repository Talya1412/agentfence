# Security Policy

Report security issues privately to repository maintainers before public disclosure. Include reproduction steps, affected version or commit, impact, and a minimal proof where safe. Do not include secrets or personal data in issues or pull requests.

AgentFence is MVP security tooling. Read [THREAT_MODEL.md](THREAT_MODEL.md) before relying on controls. The proxy is interception-layer policy, not an OS sandbox, syscall restriction, network firewall, cloud control plane, telemetry system, or prompt-injection defense.

The stdio boundary is newline-delimited and fail-closed. Frames, results, errors, and execution time are bounded by configuration. Notifications do not receive proxy responses. Unsupported `tools/list` pagination fails closed rather than returning an incomplete inventory. `require_approval` fails closed because this CLI has no trusted human approval channel.

Maintainers should confirm reports against current code and threat-model scope before publishing fixes. See [COMPATIBILITY.md](COMPATIBILITY.md) for supported message and transport boundaries.
