"""Measure a synthetic five-minute history in a disposable SQLite database."""
import argparse
import json
import platform
import sqlite3
import tempfile
import time
from pathlib import Path

from location_ledger import store


def benchmark(days=365):
    if not 1 <= days <= 366:
        raise ValueError("Choose 1-366 days")
    jsonl_bytes = 0
    count = days * 24 * 12
    base = store.epoch("2025-01-01T00:00:00Z")
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="findmy-ledger-benchmark-") as tmp:
        path = Path(tmp) / "synthetic.sqlite"
        store.initialize(path)
        with store.connect(path, write=True) as db:
            store.register(db, "synthetic-participant")
            for index in range(count):
                at_a = index % 288 < 108 or index % 288 >= 204
                observation = {
                    "observed_at": base + index * 300,
                    "latitude": 40.0 if at_a else 40.02,
                    "longitude": -75.0 if at_a else -75.03,
                    "accuracy_m": 12,
                    "source": "synthetic",
                }
                store.ingest(db, "synthetic-participant", observation,
                             received_at=observation["observed_at"] + 3)
                jsonl_bytes += len((json.dumps(observation, separators=(",", ":")) + "\n").encode())
        with store.connect(path, write=True) as db:
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            measured = store.statistics(db)
        physical_bytes = sum(p.stat().st_size for p in Path(tmp).iterdir())
    return {
        "synthetic": True, "days": days, "sample_interval_seconds": 300,
        "fresh_samples": count, **measured,
        "total_database_files_bytes_after_checkpoint": physical_bytes,
        "compact_jsonl_bytes_without_indexes": jsonl_bytes,
        "sqlite_to_jsonl_ratio": round(physical_bytes / jsonl_bytes, 3),
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
        "platform": platform.system(),
        "scope": "One participant; schema included; runtime, credentials, backups, and active WAL excluded.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=365)
    args = parser.parse_args()
    print(json.dumps(benchmark(args.days), indent=2))
