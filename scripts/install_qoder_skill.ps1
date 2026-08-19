[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ProjectPath
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ProjectPath -PathType Container)) {
    throw "Project directory does not exist: $ProjectPath"
}

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$runScript = Join-Path $repositoryRoot 'scripts\run.ps1'
$skillTemplate = Join-Path $repositoryRoot 'demos\qoder-release-demo\.qoder\skills\releaseguard\SKILL.md'

if (-not (Test-Path -LiteralPath $runScript -PathType Leaf)) {
    throw "ReleaseGuard entrypoint was not found: $runScript"
}
if (-not (Test-Path -LiteralPath $skillTemplate -PathType Leaf)) {
    throw "Qoder Skill template was not found: $skillTemplate"
}

$destinationProject = (Resolve-Path -LiteralPath $ProjectPath).Path
$skillDirectory = Join-Path $destinationProject '.qoder\skills\releaseguard'
$adapterDirectory = Join-Path $skillDirectory 'scripts'
$destinationSkill = Join-Path $skillDirectory 'SKILL.md'
$adapterPath = Join-Path $adapterDirectory 'run-releaseguard.ps1'

New-Item -ItemType Directory -Path $adapterDirectory -Force | Out-Null

$templateFullPath = [System.IO.Path]::GetFullPath($skillTemplate)
$destinationSkillFullPath = [System.IO.Path]::GetFullPath($destinationSkill)
if (-not [string]::Equals($templateFullPath, $destinationSkillFullPath, [System.StringComparison]::OrdinalIgnoreCase)) {
    Copy-Item -LiteralPath $skillTemplate -Destination $destinationSkill -Force
}

# The generated adapter is intentionally project-local. The installation root is
# resolved at install time so the committed Skill never relies on a machine path.
$escapedRepositoryRoot = $repositoryRoot.Replace("'", "''")
$adapterBody = @"
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = `$true)]
    [string[]]`$ReleaseGuardArguments
)

`$ErrorActionPreference = 'Stop'
`$releaseGuardRoot = '$escapedRepositoryRoot'
`$releaseGuardEntrypoint = Join-Path `$releaseGuardRoot 'scripts\run.ps1'

if (-not (Test-Path -LiteralPath `$releaseGuardEntrypoint -PathType Leaf)) {
    throw 'The ReleaseGuard installation used for this adapter is unavailable. Run the installer again from a valid ReleaseGuard checkout.'
}

& `$releaseGuardEntrypoint @ReleaseGuardArguments
exit `$LASTEXITCODE
"@

Set-Content -LiteralPath $adapterPath -Value $adapterBody -Encoding utf8

Write-Output "Installed the ReleaseGuard Qoder Skill adapter at: $adapterPath"
