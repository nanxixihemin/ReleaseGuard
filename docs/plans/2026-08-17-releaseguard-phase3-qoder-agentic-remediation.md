# ReleaseGuard Phase 3 Qoder Agentic Remediation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a project-level Qoder Skill that invokes the existing local ReleaseGuard audit, gives Qoder a deterministic, safety-classified remediation plan, and compares a real before/after re-audit without allowing ReleaseGuard to change the target project.

**Architecture:** Keep Phase 1 findings, score, and gate authoritative. Add a small deterministic remediation layer that converts already-produced findings into agent-facing items; it never consumes model prose as an authority and never writes to the audited project. A separate comparison contract derives resolved and remaining findings from two complete deterministic `AuditResult` documents. The Qoder Skill invokes `scripts/run.ps1`, edits only `SAFE` items when a user asks, then runs an audit again and renders the comparison.

**Tech Stack:** Python 3.10+, Pydantic v2, Typer, pytest, PowerShell, Qoder project Skills, existing local OpenVINO client/server.

---

### Task 1: Define deterministic remediation and re-audit contracts

**Files:**
- Create: `releaseguard/remediation.py`
- Modify: `releaseguard/models.py`
- Test: `tests/test_remediation.py`

**Step 1: Write failing schema and classification tests**

Cover JSON serialization for `RemediationItem`, enum values `SAFE`, `REVIEW_REQUIRED`, and `NEVER_AUTO_FIX`, and a comparison snapshot containing score, gate, severity counts, resolved findings, and remaining findings.

```python
def test_critical_secret_is_never_auto_fix() -> None:
    item = remediation_for(_finding("RG-SECRET-001", Severity.CRITICAL))
    assert item.fix_safety is FixSafety.NEVER_AUTO_FIX
    assert item.auto_fix_candidate is False
```

**Step 2: Run the focused test to prove the contract is absent**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_remediation.py -q`

Expected: collection/import failure before the new module exists.

**Step 3: Implement strict, additive Pydantic contracts**

Create `FixSafety`, `RemediationItem`, `ReAuditSnapshot`, `FindingReference`, and `ReAuditComparison`. `RemediationItem` uses the agent-facing keys `finding`, `auto_fix_candidate`, `fix_safety`, `target_file`, `recommended_action`, and `verification`, with an additional deterministic fingerprint for correlation. Add `remediation_plan` to `AuditResult` with a default empty list and preserve all existing fields and normalization behavior.

**Step 4: Implement a conservative classifier**

Allow only explicitly bounded debug-off changes, plus a production loopback replacement when the finding carries verified existing-environment-reference evidence. Mark endpoint choices without an existing reference, TODOs, Docker behavior, source maps, metadata decisions, and unknown findings as `REVIEW_REQUIRED`. Mark secrets, sensitive credential files, private-key paths, merge conflicts, data deletion, credential generation, and every Critical finding as `NEVER_AUTO_FIX`. Never accept an AI-supplied safety label or action as a way to upgrade a classification.

**Step 5: Run focused tests**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_remediation.py tests/test_models.py -q`

Expected: all focused tests pass and the old serialization assertions remain valid.

### Task 2: Attach remediation plans without changing audit authority

**Files:**
- Modify: `releaseguard/scanner.py`
- Modify: `releaseguard/rules/environment.py`
- Test: `tests/test_remediation.py`
- Test: `tests/test_hybrid_audit.py`

**Step 1: Write failing integration tests**

Assert an audit attaches exactly one deterministic plan item per finding; assert that its score, gate, findings, severities, evidence, and fingerprints equal the baseline. Add a fixture that has an explicitly named environment variable on the same configuration line and proves that only this bounded case is classified `SAFE`.

**Step 2: Implement minimal metadata evidence**

Extend only the environment finding metadata with a boolean stating whether the same assignment references a recognized runtime environment-variable form. Do not change matching, severity, score, gate, text evidence, or recommendations.

**Step 3: Attach the plan after deterministic scan completion**

Call the remediation-plan builder after deduplication and scoring. Do not inspect, mutate, remove, downgrade, or suppress findings based on an `AIReview`, including an assessment marked likely false positive.

**Step 4: Run tests**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_remediation.py tests/test_hybrid_audit.py tests/test_rules.py -q`

Expected: plan data is additive and every pre-existing deterministic result is unchanged.

### Task 3: Render and expose an honest re-audit comparison

**Files:**
- Modify: `releaseguard/remediation.py`
- Modify: `releaseguard/reporters.py`
- Modify: `releaseguard/cli.py`
- Modify: `scripts/client.py`
- Test: `tests/test_reaudit_cli.py`

**Step 1: Write failing comparison tests**

Create before/after results with a debug finding resolved and a secret remaining. Assert the comparison reports score/gate/count changes, lists the debug finding as resolved, lists the secret as remaining, and remains `BLOCKED` while the actual Critical secret finding persists.

**Step 2: Implement comparison from audit documents only**

Use deterministic finding fingerprints from the two validated `AuditResult` JSON documents. A model response must not be an input to comparison; AI review fields are retained only as report metadata. Expose a `releaseguard compare BEFORE AFTER --format json|markdown [--output PATH]` command, and route it through `scripts/run.ps1` via the existing client passthrough.

**Step 3: Add Markdown output**

Render `# ReleaseGuard Re-Audit`, Before/After score, gate and severity counts, resolved/remaining findings, and manual-intervention reason text. A persistent secret must explicitly say that rotation/removal needs manual intervention; do not imply a pass.

**Step 4: Run tests**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_reaudit_cli.py tests/test_reporting_cli.py tests/test_cli_ai.py -q`

Expected: JSON is parseable, Markdown is stable, and normal audit commands retain their behavior.

### Task 4: Create portable Qoder Skill installation and realistic demos

**Files:**
- Create: `scripts/install_qoder_skill.ps1`
- Create: `demos/qoder-release-demo/.qoder/skills/releaseguard/SKILL.md`
- Create: `demos/qoder-release-demo/src/config.ts`
- Create: `demos/qoder-release-demo/src/auth.ts`
- Create: `demos/qoder-release-demo/src/app.ts`
- Create: `demos/qoder-release-demo/package.json`
- Create: `demos/qoder-release-demo/README.md`
- Create: `demos/safe-auto-fix-demo/.qoder/skills/releaseguard/SKILL.md`
- Create: `demos/safe-auto-fix-demo/src/config.ts`
- Create: `demos/safe-auto-fix-demo/package.json`
- Create: `demos/safe-auto-fix-demo/README.md`
- Test: `tests/test_qoder_demo.py`

**Step 1: Write failing fixture tests**

Assert both project-level Skills have official `name` and focused `description` frontmatter, use a portable adapter rather than an unrecoverable absolute path, and describe natural-language/manual triggers. Audit the blocked demo and assert it includes fake-only risks, a `BLOCKED` gate, a critical secret plan item marked `NEVER_AUTO_FIX`, and at least one bounded `SAFE` plan item. Audit the safe demo and assert a `WARNING` gate which becomes `PASS` after a simulated safe debug setting edit.

**Step 2: Implement a portable adapter**

`install_qoder_skill.ps1` resolves its own repository root and writes a tiny project-local PowerShell adapter that calls the root `scripts/run.ps1`. It must support an explicit destination project, reject a missing project, and never copy the ReleaseGuard core or use an unportable hard-coded root in committed Skill instructions.

**Step 3: Implement focused Qoder `SKILL.md` instructions**

Use only Qoder-required `name` and `description` frontmatter. Cover release readiness/deployment-risk requests and `/releaseguard`; exclude ordinary UI, login, README, and CSS tasks. Require JSON audit through the adapter, require `--ai` only when available, instruct Qoder to modify only `SAFE` plan items after an explicit user request, prohibit secrets/credentials/private keys/conflicts/endpoints without an existing reference, and require a second audit plus `compare` command.

**Step 4: Build fake-only demo projects**

The blocked demo contains a clear fake token, production loopback fallback with an existing environment reference, `DEBUG=true`, and a security TODO. Its secret remains after safe changes and must retain a `BLOCKED` gate. The safe demo contains no credentials or Critical finding, starts `WARNING` from `DEBUG=true`, and reaches `PASS` only after that safe debug setting is changed.

**Step 5: Run focused tests**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_qoder_demo.py -q`

Expected: fixture behavior is deterministic and no demo has a real credential.

### Task 5: Document trigger coverage and recording flow

**Files:**
- Create: `tests/qoder_trigger_cases.md`
- Create: `docs/demo-script.md`
- Modify: `README.md`
- Modify: `docs/architecture.md`

**Step 1: Document verified official assumptions**

Record the project-level path, focused frontmatter, natural-language selection, manual `/releaseguard` invocation, restart/reload behavior, and project-level precedence from the official Qoder Skills documentation.

**Step 2: Add at least ten trigger cases**

List positive release/deployment intent phrases and negative general-development phrases. Give each one an initially unverified status column; update it only after real Qoder evidence exists. Do not label a unit test as an automatic Qoder trigger.

**Step 3: Add a 60-90 second honest demo script**

Show blocked-demo audit, local OpenVINO/device facts only when observed, user-authorized safe edits, a re-audit that stays blocked because of the fake secret, and a safe-demo optional pass path. Include intended artifact/log paths and a clear difference between verified and unverified Qoder behavior.

**Step 4: Update architectural boundaries**

Document `ReleaseGuard = read-only auditor` and `Qoder = source-modifying agent`, plus the fact that the remediation plan cannot override a deterministic finding, score, or gate.

### Task 6: Verify regression, OpenVINO path, and actual Qoder behavior

**Files:**
- Create only runtime evidence files under `docs/verification/` if the commands produce non-sensitive artifacts suitable for the repository.

**Step 1: Run all automated tests**

Run: `./.venv/Scripts/python.exe -m pytest -q`

Expected: all existing Phase 1/2 tests plus Phase 3 tests pass; the known Windows symlink test may remain skipped.

**Step 2: Run real local Skill/OpenVINO checks**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1 ai status
powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1 audit .\demos\qoder-release-demo --ai --format json
```

Record only verified model ID, device, server state, score, gate, and redacted findings.

**Step 3: Run actual Qoder verification when the IDE is installed**

Open the demo in Qoder, reload/restart Skills according to the official documentation, verify `/releaseguard`, submit at least five positive and five negative prompts, then submit the explicit safe-remediation request. Capture actual Qoder execution output/log paths and source diffs. If account/session or UI automation prevents a chat, mark only those Qoder assertions unavailable; do not infer them from tests.

**Step 4: Final report**

Report exact test count, Skill loaded status, manual/natural trigger status, Qoder invocation status, OpenVINO inference status, safe remediation status, re-audit status, before/after score and gate, resolved/remaining findings, and evidence paths. Stop after Phase 3.
