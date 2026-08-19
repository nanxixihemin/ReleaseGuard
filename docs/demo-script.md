# Phase 3 Demo Script

This is a 60–90 second demonstration of an authorized, bounded remediation.
ReleaseGuard audits only. Qoder may edit the opened demo project only after the
user explicitly authorizes a `SAFE` plan item.

## Preparation (0–10 seconds)

From the ReleaseGuard repository root, create an isolated copy of the blocked
demo, install the project-local adapter in that copy, and open the copied
project in Qoder. Do not use the checked-in fixture for an agent edit:

```powershell
$demoRunRoot = Join-Path $env:TEMP ("releaseguard-phase3-demo-" + [guid]::NewGuid().ToString('N'))
$blockedProject = Join-Path $demoRunRoot 'qoder-release-demo'
Copy-Item -Recurse -Force .\demos\qoder-release-demo $blockedProject
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_qoder_skill.ps1 -ProjectPath $blockedProject
```

Restart Qoder after installation. The official Qoder documentation requires a
restart before manually created Skills appear in the loaded Skill list. Open
`$blockedProject` as the Qoder project after the restart.

## Blocked Demo (10–55 seconds)

In the opened demo project, create a temporary evidence directory and run the
before audit through the project-local adapter:

```powershell
$reports = Join-Path $env:TEMP ("releaseguard-phase3-report-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $reports | Out-Null
$adapter = '.\.qoder\skills\releaseguard\scripts\run-releaseguard.ps1'
$aiStatus = & $adapter ai status
$aiStatus
$useAi = ($aiStatus -match '^State:\s+running$') -and ($aiStatus -match '^Model:\s+.+$') -and ($aiStatus -match '^Device:\s+.+$')
$beforeArguments = @('audit', '.', '--remediation-plan', '--format', 'json', '--output', (Join-Path $reports 'blocked-before.json'))
if ($useAi) { $beforeArguments += @('--ai', '--ai-timeout', '600') }
& $adapter @beforeArguments
```

Show the deterministic result: the fixture starts at `38 / BLOCKED`. Its fake
credential-shaped sentinel and production loopback configuration remain manual
work. The command includes `--ai --ai-timeout 600` only when `ai status`
reported a real available model and device. Do not substitute a claimed model
or device.

In Qoder, use `/releaseguard` or a release-readiness request. Then give this
explicit authorization: “Only apply the `SAFE` remediation item. Leave every
manual-review and never-auto-fix item unchanged.” The bounded edit turns the
enabled diagnostic setting off. It must not remove the sentinel, change a
service destination, or make a release decision.

Run and show the re-audit comparison:

```powershell
$afterStatus = & $adapter ai status
$afterStatus
$useAiAfter = ($afterStatus -match '^State:\s+running$') -and ($afterStatus -match '^Model:\s+.+$') -and ($afterStatus -match '^Device:\s+.+$')
$afterArguments = @('audit', '.', '--remediation-plan', '--format', 'json', '--output', (Join-Path $reports 'blocked-after.json'))
if ($useAiAfter) { $afterArguments += @('--ai', '--ai-timeout', '600') }
& $adapter @afterArguments
& $adapter compare (Join-Path $reports 'blocked-before.json') (Join-Path $reports 'blocked-after.json') --format markdown |
    Tee-Object -FilePath (Join-Path $reports 'blocked-comparison.md')
```

The expected deterministic after state is `50 / BLOCKED`. The comparison must
show the debug finding resolved and the fake credential finding remaining. Say
plainly that credential removal and rotation require manual intervention.

## Optional Safe Demo (55–90 seconds)

Create a second isolated copy before running the optional safe demo:

```powershell
$safeProject = Join-Path $demoRunRoot 'safe-auto-fix-demo'
Copy-Item -Recurse -Force .\demos\safe-auto-fix-demo $safeProject
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_qoder_skill.ps1 -ProjectPath $safeProject
```

Open `$safeProject` in Qoder, repeat the before audit, and authorize only its
`SAFE` item. The before result is `83 / WARNING`; after the bounded edit it is
`95 / PASS`. The ordinary `FIXME` remains a manual-review finding, which
demonstrates that a pass does not erase all findings.

Store the before JSON, after JSON, and Markdown comparison in the generated
`$reports` directory. When local AI runs, its operational logs remain under
`%LOCALAPPDATA%\ReleaseGuard\log`; retain only redacted artifacts.

## Verification Status

| Assertion | Evidence level |
| --- | --- |
| Project-level Skill path and focused frontmatter | Static repository test |
| Deterministic demo audit and re-audit gates | Automated ReleaseGuard test |
| Qoder reload requirement and project-level precedence | Official Qoder Skills documentation |
| Natural-language automatic selection | Live Qoder sessions: P01-P07 verified; see `tests/qoder_trigger_cases.md` |
| Negative trigger exclusion | Live Qoder sessions: N01-N05 verified without an adapter read |
| `/releaseguard` loaded and invoked in Qoder | Live Qoder Agent-mode audit; see Phase 3 runtime verification |
| Qoder-applied safe edit and re-audit | Live Qoder Agent-mode run: `38 / BLOCKED` to `50 / BLOCKED` |
| OpenVINO during Qoder invocation | Live Qoder Agent-mode `audit --ai`: completed on GPU |

Do not label a static test as proof that Qoder loaded, selected, or edited with
this Skill. The live evidence paths are retained in the Phase 3 runtime record;
the Ask-mode routing batch did not write to the isolated demo project.

## Phase 4 Human-Approval Demo

Run this section only in a fresh temporary copy. The checked-in demos remain
fixtures and must never be edited:

```powershell
$phase4Root = Join-Path $env:TEMP ("releaseguard-phase4-" + [guid]::NewGuid().ToString('N'))
$phase4Project = Join-Path $phase4Root 'qoder-release-demo'
Copy-Item -Recurse -Force .\demos\qoder-release-demo $phase4Project
New-Item -ItemType Directory -Force -Path $phase4Project\.releaseguard | Out-Null
```

Record the initial workflow audit and confirm the deterministic baseline is
`38 / BLOCKED` with `RG-SECRET-001`, `RG-ENV-001`, and `RG-DEBUG-001`:

```powershell
python -m releaseguard audit $phase4Project --remediation-plan --format json `
  --output (Join-Path $phase4Root 'phase4-before.json')
python -m releaseguard review --project $phase4Project
```

The existing Phase 3 Qoder safe authorization may then change only
`RG-DEBUG-001` (`DEBUG=true` to `false`). Re-audit and compare; the expected
state is `50 / BLOCKED`, with both protected findings still present. Start the
local dashboard against this same copy when visual review is needed:

```powershell
releaseguard dashboard --project $phase4Project --port 8765
# Open http://127.0.0.1:8765 in the local browser.
```

For the human-approved secret path, use a project whose deterministic finding
contains an assignment such as `API_KEY` and keep the real value out of all
commands and evidence. Refresh the snapshot-bound Phase 4 audit after the
safe edit, then review the plan in the loopback Dashboard:

```powershell
releaseguard review RG-SECRET-001 --project $phase4Project
# Start the Dashboard in another terminal and click the intended action:
releaseguard dashboard --project $phase4Project --port 8765
# Open http://127.0.0.1:8765, inspect RG-SECRET-001, enter a reason, and submit.
releaseguard remediate RG-SECRET-001 --project $phase4Project --format json
```

The compatibility `approve`/`reject`/`defer`/`false-positive` CLI commands are
intentionally denied. A reason or an `--actor human` argument is not a human
authorization channel.

The command validates the approval snapshot and scope, changes only the
approved source file plus an empty `.env.example` placeholder, records
`before.json`, `after.json`, `approval.json`, `remediation-plan.json`,
`diff.patch`, `audit.json`, and `timeline.json` in a new GUID directory, and
forces a deterministic re-audit. The old finding becomes `RESOLVED` only when
the scanner no longer detects it. A changed file or an extra operation makes
the command fail closed and leaves the gate unchanged. `RG-ENV-001` remains a
real blocking finding when the fixture still contains it, so the demo must not
claim `PASS` merely because an approval was recorded.

## Phase 4 Verification Boundaries

| Assertion | Evidence level |
| --- | --- |
| Approval/disposition models and redaction | Unit tests |
| Snapshot, scope, stale-approval, and re-audit behavior | Focused workflow tests |
| CLI review/approval/remediation | Typer integration tests |
| Loopback dashboard and safe rendering | HTTP integration tests + browser screenshot |
| Qoder safe edit and natural-language routing | Phase 3 live evidence; Phase 4 policy text/static checks |
| OpenVINO model/device | Phase 3 live runtime record; Phase 4 dashboard reports current status |
| Isolated Phase 4 demo | Manual/runtime record; checked-in fixtures unchanged |
