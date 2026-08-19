$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    Write-Error 'ReleaseGuard Local AI Skill requires Windows named-pipe support.'
    exit 1
}

$scriptRoot = $PSScriptRoot
$installOutput = @(& (Join-Path $scriptRoot 'install-env.ps1'))
$pythonExecutable = [string]$installOutput[-1]
$pythonExecutable = $pythonExecutable.Trim()
if (-not $pythonExecutable -or -not (Test-Path $pythonExecutable)) {
    throw 'ReleaseGuard local runtime was not created.'
}

$env:PYTHONUTF8 = '1'
& $pythonExecutable (Join-Path $scriptRoot 'client.py') @args
exit $LASTEXITCODE
