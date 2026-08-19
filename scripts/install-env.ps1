$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$runtimeHome = if ($env:RELEASEGUARD_RUNTIME_HOME) {
    $env:RELEASEGUARD_RUNTIME_HOME
} elseif ($env:LOCALAPPDATA) {
    Join-Path $env:LOCALAPPDATA 'ReleaseGuard'
} else {
    Join-Path $HOME 'AppData\Local\ReleaseGuard'
}
$venvDirectory = Join-Path $runtimeHome 'venv\releaseguard-openvino'
$venvPython = Join-Path $venvDirectory 'Scripts\python.exe'
$requirementsPath = Join-Path $projectRoot 'requirements.txt'
$stampPath = Join-Path $venvDirectory '.requirements.sha256'

function Get-ReleaseGuardSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $getFileHash = Get-Command Get-FileHash -ErrorAction SilentlyContinue
    if ($getFileHash) {
        return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash
    }

    $stream = [System.IO.File]::OpenRead($Path)
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($hasher.ComputeHash($stream))).Replace('-', '')
    } finally {
        $hasher.Dispose()
        $stream.Dispose()
    }
}

New-Item -ItemType Directory -Path $runtimeHome -Force | Out-Null

if (-not (Test-Path $venvPython)) {
    $bootstrap = Get-Command py -ErrorAction SilentlyContinue
    if ($bootstrap) {
        & $bootstrap.Source -3.11 -m venv $venvDirectory
    } else {
        $bootstrap = Get-Command python -ErrorAction Stop
        & $bootstrap.Source -m venv $venvDirectory
    }
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not create the ReleaseGuard local Python runtime.'
    }
}

$requirementsHash = Get-ReleaseGuardSha256 -Path $requirementsPath
$installedHash = if (Test-Path $stampPath) { (Get-Content -Raw $stampPath).Trim() } else { '' }
if ($requirementsHash -ne $installedHash) {
    & $venvPython -m pip install --disable-pip-version-check --upgrade pip | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not update the ReleaseGuard local Python runtime.'
    }
    & $venvPython -m pip install --disable-pip-version-check -r $requirementsPath | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not install the ReleaseGuard local OpenVINO dependencies.'
    }
    Set-Content -Path $stampPath -Value $requirementsHash -Encoding utf8
}

Write-Output $venvPython
