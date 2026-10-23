# Changelog

## 0.3.6 — 2026-10-23

- Prefer the nested body already present in NapCat's `forward.data.content`; inner numeric IDs may not be independently retrievable with `get_forward_msg`.
- Apply the existing shared depth, record, segment, text and duplicate/cycle limits to these embedded bodies; keep reference lookup for missing or empty content.
- Cover the observed payload shape and retain redaction, temporary context, tool restrictions and all configured limits.

## 0.3.5 — 2026-10-23

- Read nested forward references and inline nodes with a configurable depth limit (default 3, range 0–5, excluding the outer card).
- Share the existing record, segment, text and total-time budgets across all levels; cap external reads at 12, skip cycles and duplicates, and label unavailable or truncated nested content.
- Add an independent, empty-by-default group allowlist for text reading after native wake. Group members gain no computer access or passive-observation permission.
- Accept validated quoted forward cards and replace their quote chains before native attachment resolution, keeping unresolved quotes blocked.
- Check chat quota before fetching and recheck current authorization around each external read and before model preparation. Forward-reading turns retain the existing tool-free, temporary-reference boundary.

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
