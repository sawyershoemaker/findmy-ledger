param(
    [ValidateSet('doctor', 'install', 'status', 'stop', 'start', 'remove')][string]$Command = 'doctor',
    [ValidateSet('Live', 'Snapshot')][string]$Mode = 'Live',
    [ValidateRange(1, 86400)][int]$StationarySeconds = 300,
    [Alias('MovementMeters')][ValidateRange(1, 1000)][double]$StayRadiusMeters = 25,
    [ValidateRange(1, 86400)][int]$StayGapSeconds = 600,
    [ValidateRange(1, 300)][int]$CheckpointSeconds = 30,
    [switch]$AtStartup,
    [switch]$Retry503Locally,
    [ValidateRange(60, 3600)][int]$Interval = 300,
    [ValidateRange(0, 36500)][int]$RetentionDays = 0,
    [ValidateRange(1, 365)][int]$BackupKeep = 7,
    [string]$BackupDir,
    [string]$Python
)
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$hash = [System.Security.Cryptography.SHA256]::Create()
try { $suffix = [BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($projectRoot.ToLowerInvariant()))).Replace('-', '').Substring(0, 8) }
finally { $hash.Dispose() }
$taskName = 'FindMyLedger-' + $suffix
$watchdogName = $taskName + '-Watchdog'
$stopFile = Join-Path $projectRoot 'data\apple-auth\live-stop.request'
$restartFile = Join-Path $projectRoot 'data\apple-auth\live-restart.request'
function Stop-LedgerTask {
    New-Item -ItemType File -Path $stopFile -Force | Out-Null
    $watchdog = Get-ScheduledTask -TaskName $watchdogName -ErrorAction SilentlyContinue
    if ($watchdog -and $watchdog.State -eq 'Running') { Stop-ScheduledTask -TaskName $watchdogName }
    $current = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($current -and $current.State -eq 'Running') {
        for ($attempt = 0; $attempt -lt 12; $attempt++) {
            Start-Sleep -Seconds 1
            if ((Get-ScheduledTask -TaskName $taskName).State -ne 'Running') { break }
        }
        Stop-ScheduledTask -TaskName $taskName
    }
}
if ($Command -in @('status', 'stop', 'start', 'remove')) {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($Command -eq 'status') {
        function Read-UtcTime($value) {
            # PowerShell 7 converts ISO JSON strings to DateTime; Windows
            # PowerShell may leave strings. Preserve the zone in both cases.
            if ($value -is [DateTime]) { return ([DateTimeOffset]$value).ToUniversalTime() }
            return [DateTimeOffset]::Parse([string]$value, [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal).ToUniversalTime()
        }
        $taskInfo = if ($task) { Get-ScheduledTaskInfo -TaskName $taskName } else { $null }
        $health = [ordered]@{ task_name = $taskName; installed = [bool]$task; state = if ($task) { [string]$task.State } else { 'absent' }; last_result = if ($taskInfo) { $taskInfo.LastTaskResult } else { $null } }
        try {
            $collectorPath = Join-Path $projectRoot 'data\apple-auth\collector-status.json'
            if (Test-Path -LiteralPath $collectorPath) {
                $collectorState = Get-Content -LiteralPath $collectorPath -Raw | ConvertFrom-Json
                $health.collector_state = $collectorState.state
                $health.mode = $collectorState.mode
                $health.reason = $collectorState.reason
                $health.retry_503_policy = $collectorState.retry_503_policy
                if ($collectorState.last_poll_utc) { $health.last_poll_utc = (Read-UtcTime $collectorState.last_poll_utc).ToString('o') }
                if ($collectorState.source_observed_at_utc) {
                    $sourceTime = Read-UtcTime $collectorState.source_observed_at_utc
                    $health.source_observed_at_utc = $sourceTime.ToString('o')
                    $health.source_age_seconds_now = [long][Math]::Floor(([DateTimeOffset]::UtcNow - $sourceTime).TotalSeconds)
                }
                if ($null -ne $collectorState.next_poll_unix) {
                    $health.next_poll_utc = [DateTimeOffset]::FromUnixTimeSeconds([long]$collectorState.next_poll_unix).UtcDateTime.ToString('o')
                }
                $health.http_status = $collectorState.searchparty_response.http_status
                if ($collectorState.mode -eq 'continuous_live') {
                    $health.reports_processed = $collectorState.reports_processed
                    $health.samples_inserted = $collectorState.samples_inserted
                    $health.reports_coalesced = $collectorState.reports_coalesced
                    $health.stay_checkpoints = $collectorState.stay_checkpoints
                    $health.storage_retry_attempts = $collectorState.storage_retry_attempts
                    $health.storage_recoveries = $collectorState.storage_recoveries
                    $health.automatic_recovery = $collectorState.automatic_recovery
                    $health.history_failure_reason = $collectorState.history_failure_reason
                    $health.native_stream_connected = [bool]($task.State -eq 'Running' -and $collectorState.native_stream_connected)
                    $health.quiet_session_renewals = $collectorState.quiet_session_renewals
                    if ($collectorState.next_connect_unix -gt 0) { $health.next_connect_utc = [DateTimeOffset]::FromUnixTimeSeconds([long]$collectorState.next_connect_unix).UtcDateTime.ToString('o') }
                    $health.session = $collectorState.session
                    $health.sampling = $collectorState.sampling
                    $health.last_heartbeat_utc = $collectorState.heartbeat_utc
                    $health.status_age_seconds = [long]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [long]$collectorState.heartbeat_unix)
                    $health.native_stream_connected = [bool]($health.native_stream_connected -and $health.status_age_seconds -le 30)
                    $health.live_collection_ready = [bool]($task.State -eq 'Running' -and $health.status_age_seconds -le 30 -and $collectorState.live_collection_ready -and $health.source_age_seconds_now -le 90)
                }
            }
            $watchdogTask = Get-ScheduledTask -TaskName $watchdogName -ErrorAction SilentlyContinue
            $health.watchdog_installed = [bool]$watchdogTask
            if ($watchdogTask) {
                $health.watchdog_task_state = [string]$watchdogTask.State
                $watchdogPath = Join-Path $projectRoot 'data\apple-auth\watchdog-status.json'
                if (Test-Path -LiteralPath $watchdogPath) {
                    $watchdogStatus = Get-Content -LiteralPath $watchdogPath -Raw | ConvertFrom-Json
                    $health.watchdog = [ordered]@{
                        reason = $watchdogStatus.reason; last_action = $watchdogStatus.action
                        age_seconds = [long]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [long]$watchdogStatus.checked_at_unix)
                        restart_count = $watchdogStatus.restart_count
                        consecutive_restarts = $watchdogStatus.consecutive_restarts
                        last_restart_reason = $watchdogStatus.last_restart_reason
                    }
                }
            }
            $receiverPath = Join-Path $projectRoot 'data\apple-auth\key-listener-status.json'
            if ($collectorState.mode -ne 'continuous_live' -and (Test-Path -LiteralPath $receiverPath)) {
                $receiverState = Get-Content -LiteralPath $receiverPath -Raw | ConvertFrom-Json
                $health.receiver_state = $receiverState.state
                $health.receiver_identity_verified = $receiverState.receiver_identity_verified
                if ($receiverState.heartbeat_utc) { $health.receiver_last_heartbeat_utc = (Read-UtcTime $receiverState.heartbeat_utc).ToString('o') }
            }
        } catch { $health.diagnostics_unreadable = $true }
        $health | ConvertTo-Json
    } elseif ($Command -eq 'start' -and $task) {
        Remove-Item -LiteralPath $stopFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $restartFile -Force -ErrorAction SilentlyContinue
        Start-ScheduledTask -TaskName $taskName
        @{ task_started = $true } | ConvertTo-Json
    } elseif ($Command -eq 'stop' -and $task) {
        Stop-LedgerTask
        @{ task_stopped = $true; history_deleted = $false } | ConvertTo-Json
    } elseif ($task) {
        Stop-LedgerTask
        if (Get-ScheduledTask -TaskName $watchdogName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $watchdogName -Confirm:$false
        }
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        @{ task_removed = $true; history_deleted = $false; credentials_deleted = $false } | ConvertTo-Json
    }
    return
}
. (Join-Path $PSScriptRoot 'python-path.ps1')
$Python = Resolve-LedgerPython -ProjectRoot $projectRoot -ExplicitPython $Python
$stateDir = Join-Path $projectRoot 'data\apple-auth'
$database = Join-Path $projectRoot 'data\history.sqlite'
Push-Location -LiteralPath $projectRoot
try {
    $collectorModule = if ($Mode -eq 'Live') { 'research.live_collector' } else { 'research.collector' }
    $raw = & $Python -m $collectorModule doctor --state-dir $stateDir --db $database
    $preflightCode = $LASTEXITCODE
    $preflight = ($raw -join "`n") | ConvertFrom-Json
    if ($Command -eq 'doctor' -or $preflightCode -ne 0 -or -not $preflight.ready) {
        @{ task_name = $taskName; ready = [bool]$preflight.ready; reason = $preflight.reason; task_changed = $false; network_requests = 0 } | ConvertTo-Json
        return
    }
    $pythonWindowless = Join-Path (Split-Path -Parent $Python) 'pythonw.exe'
    if (-not (Test-Path -LiteralPath $pythonWindowless)) { throw 'This environment needs pythonw.exe for a background collector.' }
    $tokens = @('-W', 'ignore::DeprecationWarning', '-m', $collectorModule, 'run',
        '--state-dir', $stateDir, '--db', $database, '--backup-keep', [string]$BackupKeep)
    if ($Mode -eq 'Live') { $tokens += @('--stationary-seconds', [string]$StationarySeconds, '--stay-radius-m', $StayRadiusMeters.ToString([Globalization.CultureInfo]::InvariantCulture), '--stay-gap-seconds', [string]$StayGapSeconds, '--checkpoint-seconds', [string]$CheckpointSeconds) }
    else { $tokens += @('--interval', [string]$Interval) }
    if ($RetentionDays -gt 0) { $tokens += @('--retention-days', [string]$RetentionDays) }
    if ($Retry503Locally -and $Mode -eq 'Snapshot') { $tokens += '--retry-503-locally' }
    if ($BackupDir) { $tokens += @('--backup-dir', [IO.Path]::GetFullPath($BackupDir)) }
    foreach ($token in $tokens) {
        if ($token.Contains('"') -or $token.Contains("`n") -or $token.EndsWith('\')) { throw 'Invalid collector argument.' }
    }
    $arguments = ($tokens | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $action = New-ScheduledTaskAction -Execute $pythonWindowless -Argument $arguments -WorkingDirectory $projectRoot
    $settingsOptions = @{ MultipleInstances = 'IgnoreNew'; StartWhenAvailable = $true; ExecutionTimeLimit = [TimeSpan]::Zero
        AllowStartIfOnBatteries = $true; DontStopIfGoingOnBatteries = $true; Hidden = $true }
    if ($Mode -eq 'Snapshot') {
        $settingsOptions.RestartCount = 3
        $settingsOptions.RestartInterval = New-TimeSpan -Minutes 5
    }
    $settings = New-ScheduledTaskSettingsSet @settingsOptions
    if ($Mode -eq 'Live') {
        $watchdogTokens = @('-W', 'ignore::DeprecationWarning', '-m', 'research.collector_watchdog',
            '--state-dir', $stateDir, '--db', $database, '--task-name', $taskName)
        $watchdogArguments = ($watchdogTokens | ForEach-Object { '"' + $_ + '"' }) -join ' '
        $watchdogAction = New-ScheduledTaskAction -Execute $pythonWindowless -Argument $watchdogArguments -WorkingDirectory $projectRoot
        # No duration means indefinite repetition, including after future sign-ins.
        $watchdogTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
        $watchdogSettings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable `
            -ExecutionTimeLimit (New-TimeSpan -Seconds 50) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden
    }
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $description = 'FindMy Ledger: selected participant only; current-user DPAPI; respects sharing status and local pause.'
    Stop-LedgerTask
    Remove-Item -LiteralPath $stopFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $restartFile -Force -ErrorAction SilentlyContinue
    if ($AtStartup) {
        # Task Scheduler requires this Windows user's credentials for a process
        # that can access DPAPI before interactive sign-in. Never use SYSTEM/S4U.
        $credential = Get-Credential -UserName $currentUser -Message 'Windows account credentials for FindMy Ledger at startup. This is not your Apple Account password.'
        if (-not $credential -or $credential.UserName -ne $currentUser) { throw 'The task must use the Windows user who owns the DPAPI state.' }
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $definition = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Description $description
        try {
            Register-ScheduledTask -TaskName $taskName -InputObject $definition -User $currentUser `
                -Password $credential.GetNetworkCredential().Password -Force | Out-Null
            if ($Mode -eq 'Live') {
                $watchdogDefinition = New-ScheduledTask -Action $watchdogAction -Trigger @($trigger, $watchdogTrigger) -Settings $watchdogSettings `
                    -Description 'FindMy Ledger local recovery check; respects participant pause, manual stops, and authentication failures.'
                Register-ScheduledTask -TaskName $watchdogName -InputObject $watchdogDefinition -User $currentUser `
                    -Password $credential.GetNetworkCredential().Password -Force | Out-Null
            }
        } finally { $credential = $null }
    } else {
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $currentUser
        $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited
        $definition = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description $description
        Register-ScheduledTask -TaskName $taskName -InputObject $definition -Force | Out-Null
        if ($Mode -eq 'Live') {
            $watchdogDefinition = New-ScheduledTask -Action $watchdogAction -Trigger @($trigger, $watchdogTrigger) -Settings $watchdogSettings `
                -Principal $principal -Description 'FindMy Ledger local recovery check; respects participant pause, manual stops, and authentication failures.'
            Register-ScheduledTask -TaskName $watchdogName -InputObject $watchdogDefinition -Force | Out-Null
        }
    }
    if ($Mode -eq 'Snapshot' -and (Get-ScheduledTask -TaskName $watchdogName -ErrorAction SilentlyContinue)) {
        Unregister-ScheduledTask -TaskName $watchdogName -Confirm:$false
    }
    Start-ScheduledTask -TaskName $taskName
    if ($Mode -eq 'Live') { Start-ScheduledTask -TaskName $watchdogName }
    @{ task_name = $taskName; task_installed = $true; watchdog_installed = ($Mode -eq 'Live'); starts_at = if ($AtStartup) { 'windows_startup' } else { 'user_sign_in' }; live_run_verified = $false } | ConvertTo-Json
} finally { Pop-Location }
