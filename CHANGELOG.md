# Changelog

## 0.3.1 — 2026-10-22

- Add opt-in real-administrator private observations and scoped friend recall metadata (API v2).
- Allow the named fish-social command handlers to apply their own verified administrator/member checks.
- Keep ordinary private users, unrelated commands and group collection excluded by default.

## 0.3.0 — 2026-10-22

- Add dormant, opt-in immutable group observations for trusted plugins.
- Observe raw recall notices before pipeline stages and track cleaned send outcomes separately.
- Expose successful request/response preparation markers for post-security snapshots.
- Preserve existing wake gates, computer authorization, tool policy and lifecycle protection.
- Isolate observer failures from message routing and sending.
