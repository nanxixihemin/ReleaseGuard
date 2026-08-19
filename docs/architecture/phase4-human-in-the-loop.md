# Phase 4 Human-in-the-Loop Release Gate

Phase 4 extends the stable deterministic scanner with a local approval and
evidence boundary. It does not replace the scorer, the Typer CLI, or the local
OpenVINO adapter.

## Authority and State

```text
Project files
    |
    v
ProjectContext -> deterministic rules -> AuditResult -> score_and_gate
                                      |                    |
                                      v                    v
                             Finding disposition       PASS/WARNING/BLOCKED
                                      |
                         human review + ApprovalRecord
                                      |
             project snapshot + finding fingerprint + approved scope
                                      |
                         bounded, allowlisted remediation
                                      |
                         actual file hash/diff validation
                                      |
                         fresh deterministic re-audit
                                      |
                    RESOLVED only when the finding is absent
```

`Finding.status` is a workflow annotation. `APPROVED` means only that a human
authorized a remediation; it never changes `release_gate` and never implies
`RESOLVED`. The scanner continues to calculate score and gate from the actual
finding list. AI/OpenVINO/Qoder output is advisory and has no write path to
either field.

## Contracts

`releaseguard.phase4.models` defines:

- `FindingStatus`: `OPEN`, `AUTO_FIXED`, `NEEDS_REVIEW`, `APPROVED`,
  `REJECTED`, `DEFERRED`, `FALSE_POSITIVE`, `RESOLVED`.
- `ProjectSnapshot`: sorted relative file names and SHA-256 hashes with a
  canonical content hash.
- `RemediationPlan`: summary, risk, allowed files/operations, forbidden
  operations, approval requirement, expected effect, and rollback capability.
- `ApprovalRecord`: action, actor, reason, timestamp, audit run, snapshot,
  finding fingerprint, requested remediation, approved scope, and status. New
  records also carry `actor_type=human`,
  `authorization_channel=dashboard`, and a one-time authorization nonce.
  These fields are evidence, not caller-provided authority: the workflow only
  creates a record after a private Dashboard capability validates the current
  audit run, snapshot, finding fingerprint, and action.
- `TimelineEvent`: append-only event id, UTC timestamp, event type, audit run,
  finding, actor, summary, and redacted metadata.

The existing Phase 3 `RemediationItem` remains unchanged and can be projected
to a Phase 4 plan with `to_phase4_plan()`.

## Evidence and Privacy

`ReleaseWorkflow` uses `EvidenceStore` at
`<project>/.releaseguard/evidence/<random-guid>/`. Every audit and mutating
review action gets a new directory. JSON and patch artifacts are written via an
atomic, redacting persistence boundary. Evidence contains hashes, safe finding
previews, plans, approvals, diffs, audit results, and timeline events; it never
contains source bytes or raw credentials. `.releaseguard` is excluded from
future project scans.

Snapshots are content-addressed rather than Git-dependent, so a non-Git project
still gets stale-approval protection. Any changed file outside the approved
scope, unsupported operation, invalid actor, or stale snapshot fails closed and
leaves an error artifact. The workflow does not run `git reset --hard` or alter
unrelated user changes.

## Local Dashboard

`releaseguard.phase4.dashboard` uses `http.server.ThreadingHTTPServer` and no
new dependency. `create_server()` rejects every host other than
`127.0.0.1`; the default port is `8765`. The dashboard reads the same evidence
store and workflow state as the CLI and exposes score, gate, counts, safe
finding details, plan/scope, approvals, audit history, timeline, and the real
`LocalServerManager.status()` response. HTML is escaped and JSON is recursively
redacted. Review POSTs use a finding/action/audit/snapshot-bound token, are
consumed once, and route to the workflow service's private Dashboard
capability. The CLI disposition names remain compatibility stubs and fail
closed with a Dashboard authorization message.

## Failure Policy

- Missing audit, unknown finding, illegal transition, missing false-positive
  reason, or missing approval returns a user-facing error.
- Snapshot mismatch aborts remediation before source writes.
- Out-of-scope file changes or forbidden operations produce failure evidence;
  the gate remains determined by the next real audit and is never forced to
  `PASS`.
- A remaining `RG-SECRET-001` or `RG-ENV-001` continues to participate in the
  deterministic gate even after a disposition is recorded.
