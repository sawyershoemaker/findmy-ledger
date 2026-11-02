# Importing location history

Ledger accepts JSON Lines, with one observation per line. This example uses fictional coordinates:

```json
{"observed_at":"2026-09-07T13:00:00Z","latitude":40.0,"longitude":-75.0,"accuracy_m":12,"source":"synthetic"}
```

`observed_at` is the original source time, as Unix seconds or ISO 8601 with an explicit UTC offset. Source accuracy is required. Coordinates are validated and stored as integer millionths of a degree; raw provider responses are not retained.

## Import a file

```powershell
$python = '.\.venv\Scripts\python.exe'
$db = 'data/import-example.sqlite'

& $python -m location_ledger --db $db init
& $python -m location_ledger --db $db register synthetic-participant
& $python -m location_ledger --db $db import synthetic-participant `
    examples/observations.jsonl
& $python -m location_ledger --db $db place synthetic-participant `
    'Example place' 40.0 -75.0 --radius 100
& $python -m location_ledger --db $db stats
```

Imports are atomic. Exact duplicates are ignored; an invalid line or conflicting timestamp rolls back the entire import. Use `pause ALIAS` and `resume ALIAS` to control ingestion.

## Compact imported history

Ordinary imports keep every new fix. To combine stationary observations, stop other writers, preview `optimize ALIAS`, then run `optimize ALIAS --apply`. The applied operation creates a rollback snapshot. See [storage](storage.md#optimizing-existing-history) for commands and compression rules.

The separate `import --adaptive` option thins points. It does not preserve every accepted source second as stationary-run compaction does.
