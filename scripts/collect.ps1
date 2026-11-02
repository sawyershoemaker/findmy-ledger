param(
    [ValidateSet('doctor', 'once', 'run')][string]$Command = 'doctor',
    [ValidateRange(60, 3600)][int]$Interval = 300,
    [ValidateRange(0, 36500)][int]$RetentionDays = 0,
    [ValidateRange(1, 365)][int]$BackupKeep = 7,
    [switch]$Retry503Locally,
    [string]$BackupDir,
    [string]$StateDir,
    [string]$Database,
    [string]$Python
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $StateDir) { $StateDir = Join-Path $projectRoot 'data\apple-auth' }
if (-not $Database) { $Database = Join-Path $projectRoot 'data\history.sqlite' }
. (Join-Path $PSScriptRoot 'python-path.ps1')
$Python = Resolve-LedgerPython -ProjectRoot $projectRoot -ExplicitPython $Python
Push-Location -LiteralPath $projectRoot
try {
    $collectorArgs = @('-W', 'ignore::DeprecationWarning', '-m', 'research.collector', $Command,
        '--state-dir', $StateDir, '--db', $Database, '--interval', $Interval, '--backup-keep', $BackupKeep)
    if ($RetentionDays -gt 0) { $collectorArgs += @('--retention-days', $RetentionDays) }
    if ($Retry503Locally) { $collectorArgs += '--retry-503-locally' }
    if ($BackupDir) { $collectorArgs += @('--backup-dir', $BackupDir) }
    & $Python @collectorArgs
    if ($LASTEXITCODE -ne 0) { Write-Host 'Collection is not ready or needs attention; see the redacted status above.' }
} finally { Pop-Location }
