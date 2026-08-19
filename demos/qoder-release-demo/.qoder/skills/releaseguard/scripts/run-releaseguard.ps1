[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ReleaseGuardArguments
)

$ErrorActionPreference = 'Stop'
$releaseGuardRoot = $PSScriptRoot
for ($parent = 0; $parent -lt 6; $parent += 1) {
    $releaseGuardRoot = Split-Path -Parent $releaseGuardRoot
}
$releaseGuardEntrypoint = Join-Path $releaseGuardRoot 'scripts\run.ps1'

if (-not (Test-Path -LiteralPath $releaseGuardEntrypoint -PathType Leaf)) {
    throw 'The ReleaseGuard installation used for this adapter is unavailable. Run the installer again from a valid ReleaseGuard checkout.'
}

& $releaseGuardEntrypoint @ReleaseGuardArguments
exit $LASTEXITCODE
