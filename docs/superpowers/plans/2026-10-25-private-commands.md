# Private QQ commands implementation plan

> **For agentic workers:** Use superpowers:executing-plans for this bounded extension.

**Goal:** Silence QQ command entry points outside the verified administrator DM.
**Architecture:** Reversible waking preflight, late guard and output suppression.
**Tech Stack:** Existing Python/AstrBot 4.29.1, pytest; no new dependencies.
**Spec:** `docs/superpowers/specs/2026-10-25-private-commands-design.md`

## Global constraints

- Preserve tool authorization, ordinary slash wake, runtime and frozen evaluation.
- Work only in the existing `codex/response-contract` development worktree.
- Verify transport identity and effective profile; no nickname/role trust.

## Review focus

- Errors before dispatch must stay silent, including missing group subcommands.
- Alternate prefixes, @ mentions, aliases and regex handlers must be covered.
- Late identity/profile changes must not regain a command route.
- Normal wake messages and quoted command text must not become commands.
- Wrapper restoration and streaming must not leak command replies.

## Task 1: Command scope and response boundary

Files: new `command_scope.py`, `tests/test_command_scope.py`; update `main.py`,
`runtime.py` only if needed, existing command tests, README and version metadata.
Consumes: real AstrBot registry/waking stage and existing transport identity.
Produces: reversible command admission, silent event marker and guarded replies.

- [x] Add failing real-stage tests for denied commands (no sends, stopped event,
  no executed handler), private administrator pass-through and ordinary wakes.
- [x] Run the focused test file with runtime Python and test-deps. Expect denied
  inputs to fail because current handlers/errors are still visible.
- [x] Implement preflight and late denial using registry metadata, add marker
  suppression for direct/streamed/model replies and scoped model instructions.
- [x] Run focused tests. Expect all pass; update older tests only where this
  explicit policy intentionally changes their expected scope.
- [x] Run full pytest, Ruff lint/format and git diff --check. Expect all pass.
- [x] Document limits, bump to 0.3.11, review with a fresh reviewer, commit and
  push the development branch; package a distinct ZIP. Keep runtime unmodified.
