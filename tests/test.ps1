$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $projectRoot '.venv\Scripts\python.exe'
& $python -m pytest $projectRoot\tests -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& (Join-Path $projectRoot 'scripts\run.ps1') ai status
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($env:RELEASEGUARD_RUN_OPENVINO_E2E -eq '1') {
    & (Join-Path $projectRoot 'scripts\run.ps1') ai start --wait --timeout 600
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & (Join-Path $projectRoot 'scripts\run.ps1') audit (Join-Path $projectRoot 'examples\unsafe_project') --ai --ai-timeout 120
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & (Join-Path $projectRoot 'scripts\run.ps1') ai stop
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Output 'ReleaseGuard Local Skill E2E checks passed.'
