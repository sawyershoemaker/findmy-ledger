param(
    [ValidateRange(10, 90)][int]$WaitSeconds = 45,
    [switch]$NativeContext,
    [ValidateSet(1, 4)][int]$ApiVersion = 1,
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
    $probeArgs = @('-W', 'ignore::DeprecationWarning', '-m', 'research.key_probe', '--state-dir', $StateDir, '--wait-seconds', $WaitSeconds, '--api-version', $ApiVersion)
    if ($NativeContext) { $probeArgs += '--native-context' }
    & $Python @probeArgs
    if ($LASTEXITCODE -ne 0) { Write-Host 'No authenticated key was saved by this attempt. Share only the final redacted JSON status.' }
} finally { Pop-Location }
