# Collector operations

These commands assume the [Windows runtime](windows-emulator.md) is ready and the database contains the alias `participant`.

## Install and control

```powershell
$python = '.\.venv\Scripts\python.exe'
$db = 'data/history.sqlite'
& .\scripts\install-collector.ps1 -Command doctor
& .\scripts\install-collector.ps1 -Command install -Mode Live `
    -StationarySeconds 300 -StayRadiusMeters 25 `
    -StayGapSeconds 600 -CheckpointSeconds 30 `
    -BackupDir data/backups -BackupKeep 7
```

Install after `doctor` reports readiness. The collector and watchdog run as the Windows user who owns the saved account state. Their task names are `FindMyLedger-<project-path-hash>` and the same name with `-Watchdog` appended.

Tasks start at sign-in and continue while Windows is locked. After a reboot, sign in to resume collection. The optional `-AtStartup` mode requests the Windows account password for pre-sign-in startup; it may need elevated setup privileges and has not been verified. It does not use the Apple password.

| Command | Effect |
| --- | --- |
| `status` | Show collector and watchdog status |
| `stop` | Persist a manual stop, flush and exit; force-stop after 12 seconds if needed |
| `start` | Clear stop/restart markers and start collection |
| `remove` | Stop and unregister both tasks, keeping history and credentials |

For example:

```powershell
& .\scripts\install-collector.ps1 -Command status
& .\scripts\install-collector.ps1 -Command stop
& .\scripts\install-collector.ps1 -Command start
```

Reinstall the tasks if project or runtime paths change. Launchers choose Python in this order: `-Python`, `FINDMY_LEDGER_PYTHON`, `data/python-path.txt`, then the project's `.venv`.

### Storage and backups

Retention is unlimited unless `-RetentionDays` is set. `-BackupDir` enables daily SQLite snapshots; `-BackupKeep` defaults to seven. Use a dedicated directory. Rotation deletes only generated daily snapshots, leaving manual rollback backups and unrelated files alone. History snapshots exclude the rebuildable map cache.

Stationary updates checkpoint every 30 seconds by default. Transitions and orderly shutdown flush immediately; forced termination can lose the pending interval. See [storage](storage.md) for the compaction settings.

## Sessions and source freshness

Live collection owns one push/relay receiver. Stop it before running snapshot collection or a separate key listener; OS locks prevent competing receivers.

| Session setting | Default |
| --- | --- |
| Heartbeat | 30 seconds |
| Transport reconnect delay | 5–300 seconds |
| Minimum cleanup before another invitation | 30 seconds |
| Normal session renewal | 30 minutes |
| Renewal without a newer source fix | 5 minutes |
| Sharing relationship refresh | 5 minutes |

`StationarySeconds` controls quiet-session renewal, not extra stationary rows. Reconnect deadlines and HTTP 429 cooldowns survive process restarts.

`native_stream_connected` describes the transport. `live_collection_ready` also requires an authenticated source fix no older than 90 seconds. Check source age separately from process heartbeat: a connected receiver can still be waiting for the participant's phone. Older authenticated reports can backfill history without moving the latest-source status backward.

Local selection and pause state are checked about once per second and before writes. Removed sharing pauses ingestion and discards pending updates. Rejected authentication needs local attention; the collector cannot sign in automatically with a saved password.

## Automatic recovery

The watchdog checks local status, locks and Task Scheduler every minute and at sign-in. It makes no Apple or map requests.

- Unexpected exits, including exit code zero, and recoverable storage failures trigger restart.
- A new process gets three minutes to start. After that, a heartbeat older than three minutes triggers an orderly restart request. A later check can stop the task after at least 20 seconds, followed by at least 30 seconds for native cleanup.
- Repeated restarts wait 30, 60, 120, 240, 480 and then 900 seconds. Ten responsive minutes reset the streak. Apple cooldowns take precedence.
- Manual stops, paused or removed sharing, missing bootstrap, rejected authentication and corrupt or invalid history block automatic restart. A foreground collector's lock also prevents a competing task.

A responsive worker with an old location stays running; session renewal handles that case. Temporary writes get three attempts, with up to one second of lock wait each and retry delays of 0.25 and one second. Storage must become available again before a restart can recover. Missed observations cannot be reconstructed.

## Diagnostics

Status files in `data/apple-auth` are replaced on update rather than appended as per-fix logs:

| File | Contents |
| --- | --- |
| `collector-status.json` | Process heartbeat, source age, counters and policy |
| `live-session-status.json` | Protocol and session state |
| `collector-last-failure.json` | Latest classified failure, retained across restarts |
| `watchdog-status.json` | Check time, restart count, backoff and reason |
| `watchdog-error.json` | Failed check; compare with newer successful status |
| `auth-status.json` | Authentication steps and errors |

Diagnostics omit credentials, coordinates and raw exception text. Inspect relevant fields before sharing them; keep the state directory local.

## History maintenance

```powershell
& $python -m location_ledger --db $db stats
& $python -m location_ledger --db $db backup data/manual-snapshot.sqlite
& $python -m location_ledger --db data/restored.sqlite restore data/manual-snapshot.sqlite
& $python -m location_ledger --db $db pause participant
& $python -m location_ledger --db $db resume participant
```

Backup and restore destinations must be new. After resuming a participant, start the collector task if it has stopped.

Deletion commands preview their effect until `--apply` is added:

```powershell
& $python -m location_ledger --db $db retain participant `
    --before '2026-01-01T00:00:00Z'
& $python -m location_ledger --db $db forget participant
```

Retention trims history before the cutoff, including overlapping stays. Forget removes history, labels and cached areas, disables map lookups and leaves an inactive participant record. Neither changes existing backups or Apple credentials.

Stop the worker and other readers before `compact`, which reclaims unused pages after deletion. To combine stationary history, use [`optimize`](storage.md#optimizing-existing-history), which creates a rollback snapshot before applying changes.

## Snapshot mode

`research.collector` and `scripts/collect.ps1` provide snapshot polling for diagnostics. Stop Live first. Missing updates increase polling delay up to one hour; saved HTTP 429/503 `Retry-After` is honored. The research switch `--retry-503-locally` changes only bounded 503 retries. Missed polls are not replayed in a burst.

Installing `-Mode Snapshot` removes the Live watchdog and uses at most three delayed Task Scheduler retries.
