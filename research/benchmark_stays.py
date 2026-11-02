"""Reproducible storage and indexed-query measurements using synthetic history."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import sqlite3
import struct
import tempfile
import time

from location_ledger import maintenance, store
from location_ledger.history import Run


def timing_fingerprint(db, sid=1):
    digest = hashlib.sha256()
    count = 0
    for row in db.execute('SELECT * FROM samples WHERE subject_id=? ORDER BY observed_at', (sid,)):
        run = Run.from_row(row)
        for first, step, size in run.times.series(run.times.first, run.times.last+1):
            for index in range(size):
                digest.update(struct.pack('>q', first+index*step))
            count += size
    return count, digest.hexdigest()


def measure(path, start, end):
    with store.connect(path) as db:
        stats = store.statistics(db)
        began = time.perf_counter()
        report = store.report(db, 'synthetic', start, end)
        report_ms = (time.perf_counter() - began)*1000
        plan = [row['detail'] for row in db.execute('EXPLAIN QUERY PLAN SELECT * FROM samples '
            'WHERE subject_id=? AND observed_at>=? AND observed_at<? ORDER BY observed_at', (1, start, end))]
        fingerprint = timing_fingerprint(db)
        payload_bytes = db.execute('SELECT COALESCE(sum(length(detail)),0) FROM samples').fetchone()[0]
    return {**stats, 'timing_and_summary_bytes': payload_bytes,
        'range_query_plan': plan, 'bounded_report_ms': round(report_ms, 3),
        'bounded_report_observations': report['sample_count']}, fingerprint


def scenario(name, count, step, position):
    base = store.epoch('2025-01-01T00:00:00Z')
    with tempfile.TemporaryDirectory(prefix='ledger-stays-benchmark-') as temp:
        path = Path(temp)/'synthetic.sqlite'
        store.initialize(path)
        with store.connect(path, write=True) as db:
            store.register(db, 'synthetic')
            for index in range(count):
                latitude, longitude = position(index)
                stamp = base + index*step
                store.ingest(db, 'synthetic', dict(observed_at=stamp, latitude=latitude,
                    longitude=longitude, accuracy_m=5, source='synthetic'), received_at=stamp+2)
        maintenance.compact(path)
        # A bounded window near the end exercises the index, not a full history scan.
        end = base + (count-1)*step + 1
        start = max(base, end-7*86400)
        before, original = measure(path, start, end)
        optimized = maintenance.optimize(path, 'synthetic', apply=True)
        after, compacted = measure(path, start, end)
        assert original == compacted, 'Source timing/count changed during compaction'
        assert before['bounded_report_observations'] == after['bounded_report_observations']
        physical = path.stat().st_size
        return {'scenario': name, 'synthetic': True, 'source_observations': count,
            'interval_seconds': step, 'before': before, 'after': after,
            'space_reduction_percent': round((1-after['database_bytes']/before['database_bytes'])*100, 2),
            'row_reduction_percent': round((1-after['stored_rows']/before['stored_rows'])*100, 2),
            'exact_timestamp_fingerprint_matches': original == compacted,
            'standalone_database_bytes': physical,
            'scope': 'Schema and index included; point baseline uses v2 columns. Runtime, credentials, WAL and backup excluded.'}


def benchmark(days=365):
    if not 1 <= days <= 366:
        raise ValueError('Choose 1-366 synthetic days')
    def schedule(index):
        at_a = index % 288 < 108 or index % 288 >= 204
        jitter = ((index*17) % 13 - 6) / 111195
        return (40 if at_a else 40.02)+jitter, -75 if at_a else -75.03
    began = time.perf_counter()
    results = [scenario('year_of_two_recurring_places_with_jitter', days*288, 300, schedule),
        scenario('eight_hours_stationary_at_one_hz', 8*3600+1, 1,
                 lambda i: (40 + ((i*13)%9-4)/111195, -75)),
        scenario('one_hour_continuous_movement', 3600, 1,
                 lambda i: (40+i*4/111195, -75))]
    return {'synthetic': True, 'cases': results, 'elapsed_seconds': round(time.perf_counter()-began, 3),
            'python': platform.python_version(), 'sqlite': sqlite3.sqlite_version, 'platform': platform.system()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--days', type=int, default=365)
    args = parser.parse_args()
    print(json.dumps(benchmark(args.days), indent=2))
