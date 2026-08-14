# Security Policy

Report security issues privately to the repository maintainers before public disclosure. Include reproduction steps, affected version, impact, and a minimal proof where safe. Do not include secrets or personal data.

AgentFence is MVP security tooling. Read `THREAT_MODEL.md` before relying on it for controls.

The stdio boundary is newline-delimited and fail-closed. Frames, results, errors, and execution time are bounded by configuration. Notifications never receive proxy responses. This remains interception-layer policy, not an OS sandbox or network firewall.

The proxy fails closed on unsupported `tools/list` pagination instead of returning an incomplete tool inventory. `require_approval` also fails closed because this CLI has no trusted human approval channel. See `THREAT_MODEL.md` for fixed controls, deferred work, platform limits, and residual risks.
