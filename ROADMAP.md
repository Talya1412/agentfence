# Roadmap

This roadmap is directional. It does not promise delivery dates or controls outside current scope.

## Current foundation

- Bounded JSONL stdio interception.
- Fail-closed default and explicit tool decisions.
- Redaction, local audit records, bounded `tools/list` pagination, and supported input-schema checks.
- Documented limitations and local build artifacts.

## Possible next work

- Expand bounded schema keyword coverage while retaining fail-closed behavior.
- Improve process-tree termination across supported operating systems.
- Add authenticated audit sink design only with explicit key-management and deployment requirements.
- Evaluate an authenticated approval adapter with denial default and audit binding.

Out of scope for current claims: universal prompt-injection defense, OS sandboxing, DNS/network enforcement, and parser-grade SQL semantics.
