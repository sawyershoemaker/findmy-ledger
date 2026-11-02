function Resolve-LedgerPython {
    param([string]$ProjectRoot, [string]$ExplicitPython)
    if ($ExplicitPython) {
        if (-not (Test-Path -LiteralPath $ExplicitPython -PathType Leaf)) { throw 'The supplied -Python executable does not exist.' }
        return (Resolve-Path -LiteralPath $ExplicitPython).Path
    }
    $localPath = Join-Path $ProjectRoot 'data\python-path.txt'
    $candidates = @()
    if ($env:FINDMY_LEDGER_PYTHON) { $candidates += $env:FINDMY_LEDGER_PYTHON }
    if (Test-Path -LiteralPath $localPath -PathType Leaf) { $candidates += (Get-Content -LiteralPath $localPath -Raw).Trim() }
    $candidates += (Join-Path $ProjectRoot '.venv\Scripts\python.exe')
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw 'Create .venv using README.md, set FINDMY_LEDGER_PYTHON, or pass -Python with the executable path.'
}
