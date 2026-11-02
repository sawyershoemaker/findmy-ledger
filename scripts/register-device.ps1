param(
    [switch]$Doctor,
    [string]$StateDir,
    [string]$Python
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $StateDir) { $StateDir = Join-Path $projectRoot 'data\apple-auth' }
. (Join-Path $PSScriptRoot 'python-path.ps1')
$Python = Resolve-LedgerPython -ProjectRoot $projectRoot -ExplicitPython $Python
Push-Location -LiteralPath $projectRoot
try {
    $probeArgs = @('-m', 'research.device_registration', '--state-dir', $StateDir)
    if ($Doctor) { $probeArgs += '--doctor' }
    & $Python @probeArgs
    if ($LASTEXITCODE -ne 0) { Write-Host 'Registration stopped. Share only the final redacted JSON status.' }
} finally { Pop-Location }
