# Storage

Ledger combines stationary updates into one record while preserving their source times and counts. An eight-hour synthetic stream at one update per second fits in one row representing 28,801 observations.

## Schema and indexing

Schema 2 stores segments in `samples`:

| Field | Meaning |
| --- | --- |
| `subject_id`, `observed_at` | Participant and first source second; the primary key |
| `span_seconds`, `fix_count` | Time to the last source second and number of accepted observations |
| Position and accuracy | Integer coordinates and a shared uncertainty envelope |
| Receipt time and source | Latest receipt time and normalized source ID |
| `detail` | Compact metadata and exact source-time deltas |

The table uses SQLite [`WITHOUT ROWID`](https://www.sqlite.org/withoutrowid.html), so the primary key also orders the data. There is no separate row-ID index or end-time index. A range query first checks the preceding row for an overlapping stay, then reads the primary-key range. Read-only reports hold a consistent WAL snapshot across queries and labels.

Timing uses positive deltas and run-length encoding. A regular 1 Hz stream needs one delta and a repeat count; irregular timing uses the same format with zlib compression when smaller. Decoders reject malformed or oversized payloads.

## How stays are formed

| Rule | Default |
| --- | --- |
| Maximum distance from the fixed anchor | 25 metres |
| Maximum source or receipt gap | 600 seconds |
| Maximum reported accuracy radius | 100 metres |
| Maximum segment length | 7 days or 1,024 timing runs |
| Stationary checkpoint interval | 30 seconds |

Movement beyond the anchor, longer gaps, poor accuracy or a different source starts another record. The anchor stays fixed, so slow travel eventually leaves it. Its uncertainty envelope covers each fix's displacement plus reported accuracy.

Compaction retains accepted whole-second timestamps, counts and gaps. It replaces interior coordinates and individual accuracy values with the anchor and envelope, so movement within that area cannot be reconstructed. Repeated stale readings never extend a stay. A span describes observations, not uninterrupted presence or exact arrival and departure.

Exact duplicates do not add time or count. An interior replay must fit the retained envelope; new backfill inside a stay splits it into non-overlapping pieces. Reports can combine adjacent segments without filling missing timestamps.

### Multiple Live updates in one second

The first accepted value for a source second wins. A conflicting later update increments `timestamp_collision_reports` without replacing history, advancing freshness or stopping later seconds. Exact duplicates are ignored. Counts therefore represent accepted unique source seconds, not every transport message. Manual imports remain strict: conflicting timestamps roll back the import.

## Writes and reporting

The first point and movement transitions commit immediately. Stationary updates change the current row at checkpoints, including a timed flush when no new report arrives. Orderly shutdown flushes pending updates; an abrupt exit can lose the pending checkpoint interval.

Writes recheck participant status inside the transaction and stop if another writer changed the row. On restart, the recorder reloads the anchor and timing data.

Time-window queries clip timing evidence exactly. Weekly profiles count observed timestamps in local time, including daylight-saving boundaries. Retention trims an overlapping stay at the first remaining observation and adjusts its count.

Use these statistics instead of treating row count as observation count:

| Statistic | Counts |
| --- | --- |
| `stats.samples` | Represented observations |
| `stats.stored_rows` | Physical records |
| `stats.stationary_runs` | Records with multiple timestamps |

## Optimizing existing history

Schema 1 databases remain readable; new databases use schema 2. Stop the collector before an upgrade or offline compaction:

```powershell
$python = '.\.venv\Scripts\python.exe'
$db = 'data/history.sqlite'
& .\scripts\install-collector.ps1 -Command stop
& $python -m location_ledger --db $db optimize participant
& $python -m location_ledger --db $db optimize participant --apply
& .\scripts\install-collector.ps1 -Command start
```

The first `optimize` previews the change. Applying creates a `before-stays-*.sqlite` rollback snapshot, upgrades and compacts in one transaction, checks counts and integrity, then runs `VACUUM`, a WAL checkpoint and [planner optimization](https://www.sqlite.org/lang_analyze.html). Daily backup rotation leaves the rollback snapshot alone.

Use `--radius-m` and `--max-gap` for a different offline policy. Update the installed task's `StayRadiusMeters` and `StayGapSeconds` to match future collection. Reducing the radius cannot recover coordinates already discarded.

## Benchmarks

These synthetic workloads include schema and indexes but exclude runtime files, WAL and backups. The baseline stores one row per observation.

| Workload | Observations | Before | After | Rows after | Saved |
| --- | ---: | ---: | ---: | ---: | ---: |
| One year, two places, 5-minute updates with jitter | 105,120 | 3,330,048 B | 77,824 B | 731 | 97.66% |
| Eight stationary hours, 1 Hz with jitter | 28,801 | 942,080 B | 36,864 B | 1 | 96.09% |
| One moving hour, 1 Hz at 4 m/s | 3,600 | 151,552 B | 61,440 B | 515 | 59.46% |

Source-time fingerprints matched before and after. Results were generated on Windows with Python 3.13.15 and SQLite 3.50.4. Actual size depends on movement and update timing; tiny databases can gain a SQLite page when planner statistics are added.

Reproduce with `python -m research.benchmark_stays`, or read the [full results](../examples/benchmark-stays.json).

