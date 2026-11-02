param([switch]$Doctor, [string]$Python, [string]$CloudPython)
$ErrorActionPreference = 'Stop'
Write-Host 'This recovery route is on hold: the identified SharedSecrets records serve nearby finding; map-location relevance is unverified.'
Write-Host 'No password, passcode, or recovery request is needed. Native Live uses the sharing-key bootstrap.'
if (-not $Doctor) { return }
if (-not $CloudPython) { throw 'For isolated research preflight only, pass -CloudPython with its separately prepared executable.' }
$projectRoot = Split-Path -Parent $PSScriptRoot
$stateDir = Join-Path $projectRoot 'data\apple-auth'
. (Join-Path $PSScriptRoot 'python-path.ps1')
$Python = Resolve-LedgerPython -ProjectRoot $projectRoot -ExplicitPython $Python
Push-Location -LiteralPath $projectRoot
try {
    & $CloudPython -W ignore::DeprecationWarning -m research.cloudkit_unlock --state-dir $stateDir --doctor
    if ($LASTEXITCODE -ne 0) { return }
    & $Python -m research.keychain_pet --state-dir $stateDir --doctor
} finally { Pop-Location }
