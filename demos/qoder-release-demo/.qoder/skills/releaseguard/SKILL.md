---
name: releaseguard
description: >-
  Use for release-readiness, deployment-risk, or shipping decisions for this
  project, and when the user invokes /releaseguard. Do not use for ordinary UI,
  login, README, CSS, or unrelated implementation tasks.
---

# ReleaseGuard Release Review

Use this Skill only for a release or deployment decision. ReleaseGuard is a
read-only auditor; Qoder is the only component that may edit this project.

Before using the Skill, verify that the project-local adapter exists at
`.qoder/skills/releaseguard/scripts/run-releaseguard.ps1`. If it is absent,
ask the user to install it from a ReleaseGuard checkout with the supplied
installer. Do not replace the adapter with an absolute path in this file.

Check the local analyzer before the first audit:

```powershell
& .\.qoder\skills\releaseguard\scripts\run-releaseguard.ps1 ai status
```

When the status reports `State: running` and includes a real `Model` and
`Device`, include `--ai --ai-timeout 600` in the audit. Otherwise run the
deterministic audit without `--ai` and report that local AI was unavailable; do
not infer availability from installed packages or from model prose. AI output
is advisory and cannot replace deterministic findings, score, or gate.

Never quote, copy, or save raw credential or private-key text from project
source in chat, reports, or artifacts. Use the adapter's redacted JSON fields
and identify protected findings only by rule ID and file.

Create a unique evidence directory for this release-review session. Do not
reuse a prior session's `before.json` or `after.json`:

```powershell
$reportsRoot = Join-Path $env:TEMP 'releaseguard-qoder'
$reports = Join-Path $reportsRoot ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $reports | Out-Null
```

Run exactly one JSON audit through the adapter and retain it as the before
artifact. Use the first form only when the preflight reported a real local
model and device:

```powershell
& .\.qoder\skills\releaseguard\scripts\run-releaseguard.ps1 audit . --ai --ai-timeout 600 --remediation-plan --format json --output (Join-Path $reports 'before.json')
```

Otherwise use the deterministic form:

```powershell
& .\.qoder\skills\releaseguard\scripts\run-releaseguard.ps1 audit . --remediation-plan --format json --output (Join-Path $reports 'before.json')
```

Read `remediation_plan` from the JSON result. Do not edit anything unless the
user explicitly authorizes remediation. With authorization, edit only items
whose `fix_safety` is `SAFE` and whose `auto_fix_candidate` is true. Apply the
smallest change described by the plan and keep all other findings intact.

Never make automatic changes to credentials, private keys, merge-conflict
markers, service destinations, or any item marked `REVIEW_REQUIRED` or
`NEVER_AUTO_FIX`. Do not invent a production destination or convert an
unverified suggestion into a safe change.

After an authorized change, repeat the `ai status` preflight. Run exactly one
second JSON audit: use the first form only when the local model is ready, or
the deterministic form otherwise.

```powershell
& .\.qoder\skills\releaseguard\scripts\run-releaseguard.ps1 audit . --ai --ai-timeout 600 --remediation-plan --format json --output (Join-Path $reports 'after.json')
```

```powershell
& .\.qoder\skills\releaseguard\scripts\run-releaseguard.ps1 audit . --remediation-plan --format json --output (Join-Path $reports 'after.json')
```

Only after that chosen audit completes, compare the two saved documents:

```powershell
& .\.qoder\skills\releaseguard\scripts\run-releaseguard.ps1 compare (Join-Path $reports 'before.json') (Join-Path $reports 'after.json') --format markdown
```

Report resolved and remaining findings exactly as the comparison says. A
remaining credential-like finding requires manual removal and rotation; do not
present that project as releasable.

## Phase 4 human review boundary

For a Phase 4 workflow, keep the audit evidence under the project's
`.releaseguard/evidence/<guid>/` directory. A Critical or High finding is
`NEEDS_REVIEW`; tell the user that it requires human review and wait for an
explicit decision in the local Dashboard:

```powershell
releaseguard review --project .
releaseguard dashboard --project .
```

The `approve`, `reject`, `defer`, and `false-positive` CLI commands are kept
only as compatibility stubs and must fail with `Human authorization required`.
Never invoke them, pass `--actor human`, or treat a reason, `--yes`, `--force`,
or natural-language consent as authorization. The user must open the loopback
Dashboard, inspect the current finding, and submit one review action there.
After a Dashboard action creates an `ApprovalRecord`, an agent may execute the
already-approved remediation with:

```powershell
releaseguard remediate RG-SECRET-001 --project .
```

`APPROVED` records authorization only. Never mark a finding `RESOLVED`, set a
gate, or claim a release decision from model/Qoder text. Only the fresh,
deterministic re-audit after a scope-checked edit can establish `RESOLVED`.
Before remediation, validate the approval's audit run, project snapshot,
finding fingerprint, allowed files, and allowed operations. If the snapshot or
diff is stale or out of scope, fail closed and ask the user to review again.

Never approve Critical findings automatically, mark false positives without a
reason, change files outside the approved scope, create a real `.env`, print a
credential, or include raw secrets in prompts, transcripts, logs, JSON,
Markdown, dashboard pages, or evidence. Qoder may still execute the existing
explicitly authorized `SAFE` debug edit, but it cannot bypass this human-review
boundary or alter the deterministic gate.
