# Response Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox syntax for tracking.

**Goal:** Fix irrelevant permission notices and unsupported image descriptions.

**Architecture:** Change the existing guard prompt only. Reuse the isolated pilot's
read-only auth and audit guard for a bounded development evaluation.

**Tech Stack:** Python, AstrBot, pytest, existing Codex transport.

**Spec:** docs/superpowers/specs/2026-10-25-response-contract-design.md

## Global Constraints

- No permission, tool authorization, runtime persona, deployment or QQ changes.
- At most 14 isolated candidate model calls; no auth refresh or automatic retries.
- Existing A0 is the persona; S01-only improvement does not justify switching to A1.
- Evidence-based prompt validation, not string-matching tests or fabricated scores.

## Review Focus

- Tutorial/code vocabulary must not trigger a blanket permission lecture.
- Actual host operations in a group remain unavailable; transport identity wins.
- Missing images must not acquire persona-derived visual details, even as a joke.
- Attributed descriptions and real image inputs must remain useful.
- Prompt guidance applies in admin/forward modes without changing their tool rules.

### Task 1: Correct guidance and verify the actual consumers

**Files:** Modify main.py, metadata.yaml, pyproject.toml and README.md. Isolated
evaluation helpers/results live in this plan's ignored workspace and artifacts.

**Interfaces:** Consumes guard_request(event, request), unchanged authorization and
the previous pilot's frozen A0 requests. Produces revised system guidance only.

- [x] Record existing failing S16/S11 consumer outputs and passing security baseline.
- [x] Narrow group explanations and add shared visual-evidence guidance in main.py.
- [x] Run all security tests; expected: all pass, no new warnings.
- [x] Run at most 14 isolated candidate calls through guard_request and the existing
      transport; expected: relevant tutorials, honest image boundaries, real images
      usable, no tools, no QQ sends, no writes outside the evaluation root.
- [x] Inspect and record every result; block deployment on unresolved regressions.
- [x] Bump development version to 0.3.10, document limits, commit the local change.
- [x] Obtain one fresh whole-change review and address important findings before
      handing over a concrete patch and evidence. Do not deploy automatically.
