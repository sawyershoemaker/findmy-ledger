param(
    [ValidateSet('doctor', 'prepare', 'login', 'status')]
    [string]$Command = 'login',
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
    & $Python -m research.auth_probe $Command --state-dir $StateDir
    if ($LASTEXITCODE -ne 0) { Write-Host 'The probe stopped. Its redacted status above is safe to share.' }
} finally { Pop-Location }
