# ReleaseGuard Architecture

## Purpose

ReleaseGuard is a local release-readiness boundary for AI coding agents and developers. It evaluates whether a project carries recognizable pre-release risks, then returns structured findings, an explainable score, and a release gate. It deliberately separates deterministic evidence collection from optional local semantic analysis so the release remains stable, private, and useful without a model download.

## Released Four-Phase Scope

```text
Phase 1  Deterministic Release Audit
    -> Phase 2  OpenVINO Local AI Review
    -> Phase 3  Agentic Safe Remediation
    -> Phase 4  Human-in-the-loop Release Gate
```

The deterministic scanner remains authoritative throughout every phase. No
phase adds a cloud service, account system, database, CI/CD integration, or an
AI path that can set the release gate.

## Phase 1 Flow

```text
Developer or Agent
        |
        v
ReleaseGuard CLI / Python API
        |
        v
ProjectContext (bounded, read-only inventory)
        |
        v
Registered deterministic rules
        |
        v
Structured Findings -> Score policy -> Release Gate
        |                                  |
        v                                  v
Markdown / JSON report              PASS / WARNING / BLOCKED
```

`ProjectContext` owns path traversal, ignore rules, bounded text reading, project signals, and optional Git metadata. Each rule consumes that context and returns `Finding` objects rather than printing text. The scanner aggregates findings into an `AuditResult`; the score policy and reporters consume that result without needing to rescan the project.

This flow supports common release signals without assuming a single language or framework: potential credentials, development endpoints, debug settings, incomplete work markers, sensitive files, Git state, release configuration, and unwanted artifacts.

## Primary Boundaries

| Boundary | Responsibility |
| --- | --- |
| CLI / Python API | Validate the target and choose Markdown or JSON output. |
| ProjectContext | Read-only, bounded repository inventory and project detection. |
| Rules | Produce deterministic, localized facts as `Finding` values. |
| Scanner | Register and run rules, aggregate findings and scan metrics. |
| Scoring | Apply the central severity penalties and derive the gate. |
| Reporters | Render a stable `AuditResult`; never decide severity or rescan files. |
| AI protocol | Optional local OpenVINO analyzer; absent from the Phase 1 execution path. |
| Remediation plan | Converts deterministic findings into safety-classified Agent guidance; never changes findings, score, or gate. |

The central `Finding` contract is the extension point for both agent integration and AI review. It carries an id, title, severity, category, location, evidence, explanation, recommendation, confidence, metadata, and a stable fingerprint. Secret-like evidence is redacted before it reaches a report.

## Phase 2 Local AI Flow

Phase 2 adds semantic triage without moving deterministic work into a model:

```text
Qoder / Agent
  -> SKILL.md
  -> scripts/run.ps1
  -> scripts/client.py
  -> ReleaseGuard Core
  -> deterministic Findings, Score, Gate
  -> allowlisted + redacted + bounded AIAnalysisRequest
  -> \\.\pipe\releaseguard-openvino-v1
  -> persistent scripts/server.py + OpenVINO GenAI model
  -> Pydantic-validated AIReview
  -> AuditResult.ai_review
  -> original deterministic Release Gate
```

`client.py` is short-lived. It checks the named pipe, self-starts `server.py` when needed, waits through `starting -> downloading -> loading -> running`, sends one request per authenticated pipe connection, and supports graceful timeout/failure states. `server.py` downloads model files to `<model>.partial`, validates every allowlisted artifact, atomically promotes the directory, then loads one resident `LLMPipeline`. It can help distinguish contextual false positives, improve explanations, prioritize risks, summarize release readiness, and suggest safe follow-up work. It must not replace deterministic facts such as a detected secret pattern, merge conflict, or tracked sensitive file. If the analyzer is unavailable, times out, or returns invalid data, the deterministic audit remains usable and its gate remains authoritative.

## Phase 3 Qoder Remediation Flow

Phase 3 adds a project-level Qoder Skill at `.qoder/skills/releaseguard/SKILL.md`. The Skill uses `scripts/run.ps1` through a project-local adapter, requests JSON with `--remediation-plan`, and leaves source changes to Qoder after explicit user authorization.

```text
Qoder release request or /releaseguard
        |
        v
project Skill -> run.ps1 -> deterministic audit (+ optional local AI review)
        |
        v
AuditResult + deterministic remediation_plan
        |
        +-- SAFE: Qoder may make the stated bounded edit after authorization
        +-- REVIEW_REQUIRED: explain risk and wait for an operator decision
        +-- NEVER_AUTO_FIX: leave credentials, private keys, conflicts, and protected material untouched
        |
        v
Qoder edit (only when authorized) -> second deterministic audit -> compare before.json after.json
```

The remediation classifier reads only deterministic finding fields and allowlisted metadata. It does not consume `AIReview.finding_assessments[].remediation`, so a malformed or overconfident model suggestion cannot elevate a change to `SAFE` or remove a deterministic finding. The re-audit compares two actual `AuditResult` documents; it does not infer resolution from model text.

## ADRs

### ADR-001: Local-First, Read-Only Auditing

**Decision:** Phase 1 reads a local project directory and performs no network upload, project-code execution, dependency installation, source mutation, deletion, or Git mutation.

**Trade-off:** ReleaseGuard cannot validate live infrastructure or hosted policy state. The result is a safer and more predictable audit surface for sensitive repositories.

### ADR-002: Deterministic Rules Before AI

**Decision:** Core checks are normal rule implementations, not prompts or model judgments. The AI layer is a later, optional localhost adapter.

**Trade-off:** Phase 1 cannot understand every business nuance, but it is reproducible, testable, fast, and useful without hardware-specific model setup.

### ADR-003: Findings Are Structured Data

**Decision:** Rules return `Finding` values and all output derives from `AuditResult`.

**Trade-off:** Rules need a small shared data model, but JSON consumers, Markdown reports, score tests, remediation agents, and a future AI service all get the same stable contract.

### ADR-004: One Project Context Per Audit

**Decision:** File enumeration, ignore handling, bounded reads, and project detection happen through a single context rather than each rule walking the repository independently.

**Trade-off:** Context has a broader responsibility, but audits avoid repeated I/O and can report files scanned and skipped consistently.

### ADR-005: AI Is a Local Named-Pipe Enrichment Boundary

**Decision:** The optional analyzer communicates over an authenticated Windows named pipe using bounded UTF-8 JSON, with explicit status states, timeouts, and Pydantic schema validation. The standalone Skill client self-spawns the persistent server because this project is not tied to the reference host's process manager.

**Trade-off:** There is an extra client/server boundary and first-run model download, but the scanner is not coupled to OpenVINO imports, a remote service, or a model lifecycle. The server never opens a localhost TCP port, and source never leaves the device.

### ADR-006: Explicitly Bounded Remediation

**Decision:** The audit core remains read-only. An external AI Coding Agent may
perform only an explicitly authorized `SAFE` edit. Protected remediation uses
the Phase 4 local workflow only after a current Dashboard authorization binds
the audit, finding, snapshot, and allowed scope; every edit is re-audited.

**Trade-off:** ReleaseGuard cannot silently repair all release risks. This
prevents it from inventing endpoints, changing credentials, rotating secrets,
resolving conflicts, deleting user data, or making an unreviewed deployment
decision.

## Failure And Security Handling

- An invalid project path should produce a clear CLI error rather than a Python traceback for ordinary users.
- Missing Git, a non-Git directory, and unreadable Git metadata should degrade Git checks gracefully rather than failing the audit.
- Binary, oversized, ignored, unreadable, and symlink-loop-prone paths are skipped according to the context policy; they are never executed.
- A malformed or inaccessible file should not expose source content in an error message. Scan metrics make skipped work visible.
- An unexpected rule failure becomes a low-severity scanner diagnostic while the remaining registered rules continue to run.
- Secret candidates are redacted before they enter reports or agent-facing output. A raw credential must not be echoed just because a rule matched it.
- Local AI requests have strict finding and text-count caps, source-line-local redaction, pipe message size limits, timeouts, Pydantic schema validation, and a deterministic fallback. No source upload or cloud inference is used by the architecture.
- `NEVER_AUTO_FIX` covers protected credentials, private keys, sensitive material, merge conflicts, and other irreversible state. `REVIEW_REQUIRED` covers endpoint choices and release-policy decisions. Only explicitly allowlisted, reversible configuration changes receive `SAFE`.
- Re-audit resolution is determined by the later deterministic scan. A moved secret line remains a finding through conservative identity matching, and an advisory AI false-positive assessment never unblocks it.

## Phase 4 Human-in-the-Loop Flow

Phase 4 keeps the Phase 1-3 scanner and adds a local workflow service:

```text
Audit -> redacted GUID evidence -> Finding status
  -> human ApprovalRecord (finding fingerprint + audit run + snapshot + scope)
  -> allowlisted edit -> real hash/diff validation -> deterministic re-audit
  -> timeline + updated gate
```

`releaseguard.phase4.ReleaseWorkflow` is the only mutation boundary. It can
record `APPROVE_REMEDIATION`, `REJECT`, `DEFER`, and
`MARK_FALSE_POSITIVE` actions, but an approval is not a resolution. A fresh
scan must stop reporting the finding before the workflow records `RESOLVED`.
Critical findings default to `NEEDS_REVIEW`; AI, Qoder, and OpenVINO have no
API that can set a finding status to resolved or write a release gate.

`EvidenceStore` writes append-only random GUID directories under
`.releaseguard/evidence/`, plus a redacted state index for local consumers.
Snapshots hash relative file contents and exclude `.releaseguard`, so adding
evidence cannot create findings on the next audit. Before a remediation write,
the service compares the approval snapshot to the current project, validates
allowed files and operations, and fails closed on any mismatch. It never uses
an unrestricted Git reset.

The optional standard-library dashboard binds only to `127.0.0.1:8765` and
reads this same state. It escapes HTML, redacts JSON, shows actual local
OpenVINO status, and routes review actions back through the workflow.

## Extension Path

New framework-specific checks fit behind the existing rule interface. New renderers consume `AuditResult`. Agent integrations call the stable `scripts/run.ps1` entrypoint and use JSON for structured decisions. The OpenVINO service remains an adapter over the established finding schema, which keeps future policy work additive rather than a rewrite.
