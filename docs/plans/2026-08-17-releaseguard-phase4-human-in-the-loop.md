# ReleaseGuard Phase 4 Human-in-the-Loop Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a local, auditable human approval loop around the stable Phase 1-3 scanner without allowing AI to set the gate or resolve findings.

**Architecture:** Extend the existing Pydantic contracts with disposition, approval, remediation-scope, snapshot, and timeline models. Add a small file-backed workflow service under `releaseguard/phase4` that writes a new GUID evidence directory per action, redacts sensitive values before persistence, validates project snapshots and diffs, and invokes the existing deterministic scanner for every re-audit. Keep Typer as the CLI boundary and use a standard-library HTTP server with escaped HTML for the dashboard; both surfaces call the same workflow service.

**Tech Stack:** Python 3.10+, Pydantic 2, Typer, `http.server`, `html`, `hashlib`, `difflib`, pytest. No new runtime dependency.

---

## Task 1: Phase 4 contracts and redaction

**Files:**
- Modify: `releaseguard/models.py`
- Modify: `releaseguard/remediation.py`
- Create: `releaseguard/phase4/__init__.py`
- Create: `releaseguard/phase4/models.py`
- Create: `releaseguard/phase4/redaction.py`
- Test: `tests/test_phase4_models.py`

1. Add `FindingStatus`, `ApprovalAction`, `ApprovalStatus`, `TimelineEventType`, `ProjectSnapshot`, `RemediationPlan`, `ApprovalRecord`, and `TimelineEvent` with strict Pydantic validation and JSON-safe enum values.
2. Add a non-authoritative disposition field to `Finding` (default `OPEN`) while preserving existing serialized keys and fingerprints. Never allow a constructor or AI payload to claim `RESOLVED` as evidence of a fix.
3. Convert existing deterministic `RemediationItem` data into a Phase 4 `RemediationPlan` without changing Phase 3 output behavior.
4. Implement centralized redaction for credential-like literals, including nested mappings/lists and free-form evidence, and reject raw-secret persistence paths.
5. Test enum round trips, approval identity fields, required false-positive reasons, approved-versus-resolved semantics, snapshot hashes, and secret redaction.

## Task 2: Evidence store, snapshots, and timeline

**Files:**
- Create: `releaseguard/phase4/store.py`
- Create: `releaseguard/phase4/snapshots.py`
- Create: `releaseguard/phase4/timeline.py`
- Test: `tests/test_phase4_store.py`

1. Build a project snapshot from relative file paths and SHA-256 content hashes, excluding the evidence directory and common VCS/cache paths.
2. Create an evidence root under `<project>/.releaseguard/evidence`; each action gets a cryptographically random GUID directory and atomically written JSON/text artifacts.
3. Persist only redacted audit, approval, plan, diff, and timeline payloads. Never log or serialize raw file contents; preserve safe previews only.
4. Provide latest-audit/approval lookup and append-only timeline loading, tolerating missing optional artifacts.
5. Test unique directories, round-trip serialization, traversal rejection, exclusion rules, and raw-secret absence in every written artifact.

## Task 3: Workflow and fail-closed remediation

**Files:**
- Create: `releaseguard/phase4/workflow.py`
- Modify: `releaseguard/scanner.py` (only to expose a Phase 4-safe audit identity helper if needed)
- Test: `tests/test_phase4_workflow.py`

1. Implement `audit_and_record` to save an authoritative audit run, emit timeline events, assign `NEEDS_REVIEW` for protected findings, and calculate gate only through `score_and_gate`.
2. Implement review/disposition actions (`approve`, `reject`, `defer`, `false_positive`) with legal transition checks, mandatory reasons where required, actor validation, finding fingerprint binding, audit-run binding, snapshot binding, and approved scope binding.
3. Implement `remediate` for the explicit demo-safe secret migration and existing safe debug fix. Validate the approval, current snapshot, file hashes, allowed files, allowed operations, and forbidden operations before writing anything.
4. Capture before/after snapshots and a redacted unified diff. If any unauthorized file or operation is detected, fail closed, retain evidence, and avoid destructive rollback of unrelated user changes.
5. Force a fresh deterministic audit after a successful change. Mark a finding `RESOLVED` only when the fresh scan no longer contains its identity; keep approvals separate from resolution and preserve blocking findings/gate.
6. Test every transition, stale approval, scope violation, forbidden operation, unauthorized agent claim, successful isolated remediation, and re-audit-controlled resolution.

## Task 4: Typer human-review commands

**Files:**
- Modify: `releaseguard/cli.py`
- Test: `tests/test_phase4_cli.py`

1. Add `review [FINDING_ID]`, `approve`, `reject`, `defer`, `false-positive`, and `remediate` commands with project/evidence options that default to the current project and `.releaseguard` store.
2. Render safe text/JSON only; require `--reason` for false positives (and support approval reasons), return non-zero errors for missing/stale/invalid records, and never accept a caller-supplied gate or resolved status.
3. Keep all existing command signatures and output contracts unchanged. Add a `--format json` path for automation without exposing evidence secrets.

## Task 5: Local dashboard

**Files:**
- Create: `releaseguard/phase4/dashboard.py`
- Modify: `releaseguard/cli.py`
- Test: `tests/test_phase4_dashboard.py`

1. Implement a standard-library HTTP server bound strictly to `127.0.0.1`, default port `8765`, with an injectable server factory for tests.
2. Render score, gate, severity counts, safe finding previews, details, remediation plans, approval history, audit history, timeline, and actual `LocalServerManager.status()` data.
3. Add POST review actions with CSRF-like action tokens tied to the displayed finding and mandatory false-positive reason; route all mutations through the workflow service.
4. Escape all rendered content and add responsive, readable styling without a frontend dependency. Test bind host, endpoint content, no raw secret, and review action evidence.

## Task 6: Qoder/docs/demo and verification

**Files:**
- Modify: `demos/qoder-release-demo/.qoder/skills/releaseguard/SKILL.md`
- Modify: `demos/safe-auto-fix-demo/.qoder/skills/releaseguard/SKILL.md`
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/demo-script.md`
- Create: `docs/architecture/phase4-human-in-the-loop.md`
- Create: `docs/verification/phase4-runtime-verification-2026-08-17.md`
- Create: `scripts/phase4_demo.ps1`
- Test: `tests/test_qoder_demo.py` (focused additions only)

1. Document that Qoder may propose or execute only approved safe work, must request human review for HIGH/CRITICAL findings, and cannot alter gate/status or echo secrets.
2. Run the Phase 4 demo exclusively in a temporary isolated copy: audit, safe debug remediation, re-audit, approve the secret migration, validate scope/diff, re-audit, and preserve `RG-ENV-001`/`BLOCKED` when applicable.
3. Record separate unit, integration, manual, Qoder, and OpenVINO/GPU verification results; label unavailable real checks `NOT VERIFIED`.
4. Run the full baseline plus focused Phase 4 suite, inspect changed files, and capture a dashboard screenshot.

