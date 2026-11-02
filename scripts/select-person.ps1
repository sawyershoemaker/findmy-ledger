param(
    [ValidateSet('discover', 'select')]
    [string]$Command = 'select',
    [string]$Python
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$stateDir = Join-Path $projectRoot 'data\apple-auth'
. (Join-Path $PSScriptRoot 'python-path.ps1')
$Python = Resolve-LedgerPython -ProjectRoot $projectRoot -ExplicitPython $Python
Push-Location -LiteralPath $projectRoot
try {
    & $Python -m research.people_probe $Command --state-dir $stateDir
    if ($LASTEXITCODE -ne 0) { Write-Host 'The probe stopped. Share only the final JSON status.' }
} finally { Pop-Location }
