[CmdletBinding()]
param(
    [string]$ProjectRoot = (Get-Location).Path,
    [switch]$KeepCopy
)

$ErrorActionPreference = 'Stop'
$runRoot = Join-Path $env:TEMP ("releaseguard-phase4-demo-" + [guid]::NewGuid().ToString('N'))
$sourceDemo = Join-Path $ProjectRoot 'demos\qoder-release-demo'
$project = Join-Path $runRoot 'qoder-release-demo'
$reports = Join-Path $runRoot 'evidence'
New-Item -ItemType Directory -Force -Path $runRoot, $reports | Out-Null
Copy-Item -Recurse -Force $sourceDemo $project

function Invoke-ReleaseGuard {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    & python -m releaseguard @Arguments
    if ($LASTEXITCODE -ne 0) { throw "ReleaseGuard command failed with code $LASTEXITCODE" }
}

$before = Join-Path $reports 'before.json'
$afterSafe = Join-Path $reports 'after-safe.json'
$afterHuman = Join-Path $reports 'after-human.json'

Write-Host "Isolated project: $project"
Invoke-ReleaseGuard @('audit', $project, '--remediation-plan', '--format', 'json', '--output', $before)
Write-Host "Initial audit saved (raw credentials are not printed)."

# This is the Phase 3 SAFE authorization performed inside the isolated copy.
$config = Join-Path $project 'src\config.ts'
if (Test-Path $config) {
    $source = Get-Content -Raw -LiteralPath $config
    $updated = $source -replace '(?i)(\bDEBUG\s*=\s*)true\b', '${1}false'
    if ($updated -ne $source) {
        Set-Content -LiteralPath $config -Value $updated -NoNewline
    }
}
Invoke-ReleaseGuard @('audit', $project, '--remediation-plan', '--format', 'json', '--output', $afterSafe)
Write-Host "Safe re-audit saved; compare with the Phase 3 result before continuing."

# Phase 4 human approval is explicit and recorded in the isolated project's
# GUID evidence store. `review` creates the persistent, snapshot-bound Phase 4
# audit record; the legacy report-only `audit` commands above intentionally do
# not create one. High-risk disposition CLI commands are compatibility stubs,
# so the operator must use the loopback Dashboard as the authorization channel.
Invoke-ReleaseGuard @('review', 'RG-SECRET-001', '--project', $project, '--format', 'json')
Write-Host "Open the Dashboard in another terminal:"
Write-Host "  python -m releaseguard dashboard --project $project --port 8765"
Write-Host "Review RG-SECRET-001 at http://127.0.0.1:8765 and submit the human action."
[void](Read-Host "Press Enter after the Dashboard action is recorded")
Invoke-ReleaseGuard @('remediate', 'RG-SECRET-001', '--project', $project, '--format', 'json')
Invoke-ReleaseGuard @('audit', $project, '--remediation-plan', '--format', 'json', '--output', $afterHuman)

Write-Host "Phase 4 evidence directory: $($project)\.releaseguard\evidence"
Write-Host "Human-approved re-audit saved: $afterHuman"
Write-Host "The environment finding remains blocking when its source condition remains present."

if (-not $KeepCopy) {
    Write-Host "Temporary copy retained for inspection at $runRoot (remove it after review)."
}
