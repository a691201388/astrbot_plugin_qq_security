# Administrator ZIP Inbox Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline, task by task.

**Goal:** Receive administrator private ZIPs and expose them to existing Codex tasks.
**Architecture:** Reversible adapter preservation, authenticated bounded inbox,
then private-only metadata injection and Codex handoff.
**Tech Stack:** Python, AstrBot 4.29.1, aiocqhttp, zipfile, pytest.
**Spec:** ../specs/2026-10-24-admin-zip-inbox-design.md

## Global Constraints
- One ZIP/turn, 32 MiB compressed, 1000 entries, 256 MiB expanded, five files/actor.
- 24-hour eligibility; expired copies cleaned on next receipt, serialized with use.
- Private current double-listed administrator only; no extraction/execution on receipt.
- No new dependencies, core patch, model test call or QQ test message.

## Review Focus
- Quoted files retain source sender/account and cannot import a group file.
- Lost authority during download never publishes an attachment or starts Codex.
- URLs, UNC paths and symlinks from get_file are rejected before reading.
- Invalid/oversized ZIPs leave no owned temporary copy.
- A running Codex task keeps its inputs until completion.

### Task 1: Preserve and receive private attachments
Files: new attachments.py, tests/test_attachments.py.
Interfaces: PendingZip(File), AttachmentAdapterGuard.install/restore,
ZipInbox.receive(event, reference, actor, allowed), recent(actor), lock(actor).
- [x] Write failing tests for direct and quoted conversion, bounded copy, rejection,
      authority revocation, expiration, actor isolation and deduplication.
- [x] Observe failure; implement inert adapter hook and bounded local inbox.
- [x] Run pytest tests/test_attachments.py; expect all pass. Commit implementation.

### Task 2: Integrate and verify
Files: main.py, tests/test_attachments.py, README.md, CHANGELOG.md, metadata.yaml.
Interfaces: consume Task 1 helpers; no new external tool.
- [x] Write failing integration tests for private receipt, rejected group/nonadmin,
      next-turn metadata, quoted source validation and Codex path handoff.
- [x] Observe failure, implement pipeline normalization and private Codex handoff.
- [x] Run full suite and Ruff; review the complete diff in fresh context.
- [x] Backup, install/reload and replay actual ZIP without model/QQ sends.
- [ ] Commit and push existing codex/fish-social-events branch, verify hashes.

Already-authorized live installation and security-plugin GitHub updates apply.
