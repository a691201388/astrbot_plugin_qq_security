# Changelog

## 0.3.4 — 2026-10-23

- Read directly received merged-forward text only for the current verified private QQ administrator, through the matching OneBot account.
- Limit retrieval time, cards, records, segments and text; omit media and nested forwards without resolving their resources.
- Treat forwarded text and nicknames as redacted temporary references; keep them out of the sender's observed text and native persistent input history.
- Make forward-reading turns tool-free, including call-time denial of guarded tools and direct computer/workspace entry points. Ordinary administrator turns retain their existing permissions.
- Give specific feedback for unavailable records and quoted cards; preserve cancellation and recheck authorization after retrieval.
- Block unresolved QQ quotes and disable native remote fallback on validated quote chains so nested forwards cannot bypass the new boundary.
- Reject the incompatible empty-tool `skills_like` runner mode with a clear setting hint; current `full` mode remains supported.

## 0.3.3 — 2026-10-23

- Send a short progress notice before an authorized private administrator's Codex task, once per incoming event even with concurrent tool calls.
- Bound the notice send to five seconds; keep task results unchanged on send failure and preserve cancellation.
- Recheck administrator authorization after the notice before starting computer execution.

## 0.3.2 — 2026-10-23

- Exclude parsed Fish Social management commands from text observation by stable original command identity, without changing command authorization.
- Strictly redact observation text and nicknames before limits, including computer-admin sends; leave live request/send permissions unchanged.
- Drop text observations exceeding 100 components rather than retaining partially redacted prefixes.
- Advertise command-exclusion capability and add opt-in peer-less bot recall metadata for upgraded consumers; legacy subscriptions do not receive the new semantic.

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
