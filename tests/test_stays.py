import hashlib
from contextlib import closing
import json
from pathlib import Path
import random
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import zlib

from location_ledger import maintenance, store
from location_ledger.history import Run, StayPolicy, Times, range_rows
from location_ledger.profile import weekly_profile
from location_ledger.stay_recorder import StayRecorder

BASE = store.epoch('2026-01-05T12:00:00Z')


def point(offset=0, north=0, **changes):
    result = dict(observed_at=BASE+offset, latitude=40+north/111195, longitude=-75,
                  accuracy_m=5, source='synthetic')
    result.update(changes)
    return result


def expanded(times):
    return [first+i*step for first, step, count in times.series(times.first, times.last+1) for i in range(count)]


class StayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'history.sqlite'
        store.initialize(self.path)
        with store.connect(self.path, write=True) as db:
            store.register(db, 'participant')
        self.recorder = StayRecorder(self.path, 'participant')

    def add(self, offset=0, north=0, **changes):
        return self.recorder.accept(point(offset, north, **changes), received_at=BASE+offset+2)

    def runs(self):
        with store.connect(self.path) as db:
            return [Run.from_row(r) for r in db.execute('SELECT * FROM samples ORDER BY observed_at')]

    def report(self, start=BASE, end=BASE+86400, **options):
        with store.connect(self.path) as db:
            return store.report(db, 'participant', start, end, **options)

    def test_hour_of_one_hz_jitter_is_one_row_with_exact_timing(self):
        # Exercise the real writer and its checkpoints, not just a geometry helper.
        for second in range(3601):
            self.add(second, north=second % 7 - 3)
        self.recorder.flush()
        run, = self.runs()
        self.assertEqual(run.times.count, 3601)
        self.assertEqual(run.times.last-run.times.first, 3600)
        self.assertLess(len(run.payload()), 40)
        self.assertLessEqual(run.spread_dm, 61)
        result = self.report()
        self.assertEqual(result['sample_count'], 3601)
        self.assertEqual(result['spans'][0]['observed_span_seconds'], 3600)
        self.assertNotIn('latitude', json.dumps(result))

    def test_fixed_anchor_does_not_swallow_slow_travel(self):
        for second in range(101):
            self.add(second, north=second)
        self.recorder.flush()
        runs = self.runs()
        self.assertGreaterEqual(len(runs), 4)
        self.assertTrue(all(r.spread_dm <= 251 for r in runs))
        self.assertEqual(sum(r.times.count for r in runs), 101)
        self.assertGreater(len(self.report()['spans']), 1)  # unlabelled travel is not one stay

    def test_gap_and_bad_accuracy_split_stays(self):
        for offset in (0, 300, 600, 1201, 1501):
            self.add(offset)
        self.add(1502, accuracy_m=300)
        self.add(1503)
        self.recorder.flush()
        self.assertEqual([r.times.count for r in self.runs()], [3, 2, 1, 1])
        report = self.report(max_gap=600)
        self.assertEqual(report['gaps'][0]['seconds'], 601)
        self.assertIn('low_accuracy', [s['quality'] for s in report['spans']])

    def test_receipt_outage_is_a_boundary(self):
        self.add()
        self.recorder.accept(point(1), received_at=BASE+1000)
        self.assertEqual(len(self.runs()), 2)

    def test_checkpoint_is_update_not_an_additional_row_and_survives_restart(self):
        for offset in (0, 1, 30, 60):
            self.add(offset)
        self.assertEqual(len(self.runs()), 1)
        self.recorder = StayRecorder(self.path, 'participant')
        self.add(61)
        self.recorder.flush()
        self.assertEqual(self.runs()[0].times.count, 5)
        self.assertEqual(self.runs()[0].times.first, BASE)

    def test_legacy_sampler_resumes_at_actual_end_of_compacted_history(self):
        from location_ledger.sampling import AdaptiveSampler
        self.add()
        self.add(30, north=4)
        with store.connect(self.path) as db:
            sampler = AdaptiveSampler.from_database(db, 'participant')
        self.assertEqual(sampler.latest.observed_at, BASE+30)
        self.assertEqual(sampler.latest.lat_e6, self.runs()[0].last_lat_e6)

    def test_failed_commit_does_not_advance_in_memory_stay(self):
        self.add()
        previous = self.recorder.current
        with patch('location_ledger.stay_recorder.write_run', side_effect=sqlite3.OperationalError('Synthetic full disk')):
            with self.assertRaises(sqlite3.OperationalError):
                self.add(30)
        self.assertEqual(self.recorder.current, previous)
        self.assertEqual(self.runs()[0].times.count, 1)
        self.add(30)
        self.assertEqual(self.runs()[0].times.count, 2)

    def test_bounded_irregular_timing_chunks_preserve_all_observations(self):
        from location_ledger.history import MAX_PAIRS
        stamp = 0
        for i in range(MAX_PAIRS+5):
            self.add(stamp)
            stamp += 2+i%2
        self.recorder.flush()
        runs = self.runs()
        self.assertEqual(sum(r.times.count for r in runs), MAX_PAIRS+5)
        self.assertEqual(len(runs), 2)
        self.assertTrue(all(len(r.times.pairs) <= MAX_PAIRS for r in runs))

    def test_dense_profile_counts_observations_without_expanding_each_one(self):
        from location_ledger.history import write_run
        from dataclasses import replace
        self.add()
        run = self.runs()[0]
        run = replace(run, times=Times(BASE, ((1, 7200),)), last_received_at=BASE+7202,
                      received_at=BASE+7202)
        with store.connect(self.path, write=True) as db:
            write_run(db, 1, run)
        with store.connect(self.path) as db:
            result = weekly_profile(db, 'participant', BASE+1800, BASE+5400, timezone_name='UTC')
        self.assertEqual(result['sample_count'], 3600)
        self.assertEqual([c['sample_count'] for c in result['cells']], [1800, 1800])

    def test_replays_never_extend_duration_or_counts(self):
        self.add()
        self.add(1, north=3)
        self.add(30)
        self.recorder = StayRecorder(self.path, 'participant')
        for offset in (0, 1, 30):
            result = self.recorder.accept(point(offset, north=3 if offset == 1 else 0), received_at=BASE+1000)
            self.assertEqual(result['duplicates'], 1)
        with self.assertRaisesRegex(ValueError, 'Conflicting'):
            self.recorder.accept(point(1, north=100), received_at=BASE+1000)
        self.assertEqual(self.runs()[0].times.count, 3)
        self.assertEqual(self.runs()[0].received_at, BASE+32)

    def test_backfill_splits_a_compacted_stay_without_overlap_or_loss(self):
        for offset in (0, 30, 60, 90):
            self.add(offset)
        self.add(45, north=500)
        runs = self.runs()
        self.assertEqual([expanded(r.times) for r in runs], [[BASE, BASE+30], [BASE+45], [BASE+60, BASE+90]])
        self.assertEqual(self.report()['sample_count'], 5)
        self.add(100)
        self.recorder.flush()
        self.assertEqual(sum(r.times.count for r in self.runs()), 6)

    def test_partial_window_includes_overlapping_predecessor_and_exact_counts(self):
        for offset in (0, 60, 120, 180, 240, 300):
            self.add(offset)
        result = self.report(BASE+61, BASE+240)
        self.assertEqual(result['sample_count'], 2)
        self.assertEqual(result['spans'][0]['first_observed_at'], store.iso(BASE+120))
        self.assertEqual(result['spans'][0]['last_observed_at'], store.iso(BASE+180))
        self.assertEqual(self.report(BASE+1, BASE+59)['sample_count'], 0)

    def test_stricter_report_gap_splits_timing_without_invented_observations(self):
        for offset in (0, 10, 310, 320):
            self.add(offset)
        self.recorder.flush()
        report = self.report(max_gap=60)
        self.assertEqual([s['sample_count'] for s in report['spans']], [2, 2])
        self.assertEqual(report['gaps'][0]['seconds'], 300)

    def test_spatial_envelope_prevents_false_place_certainty(self):
        with store.connect(self.path, write=True) as db:
            store.add_place(db, 'participant', 'Small place', 40, -75, 20)
        self.add()
        self.add(30, north=20)
        self.assertIsNone(self.report()['spans'][0]['place'])
        self.assertGreaterEqual(self.runs()[0].accuracy_dm, 250)

    def test_retention_clips_inside_stay_and_counts_exactly(self):
        for offset in (0, 30, 60, 90):
            self.add(offset, north=offset/10)
        with store.connect(self.path) as db:
            preview = maintenance.retain(db, 'participant', BASE+45)
        self.assertEqual(preview['eligible_samples'], 2)
        self.assertEqual(self.runs()[0].times.count, 4)
        with store.connect(self.path, write=True) as db:
            maintenance.retain(db, 'participant', BASE+45, apply=True)
        run, = self.runs()
        self.assertEqual(expanded(run.times), [BASE+60, BASE+90])
        self.assertFalse(run.exact_endpoints & 1)
        self.assertEqual(self.report()['sample_count'], 2)

    def test_pause_discards_buffer_and_cannot_checkpoint_it(self):
        self.add()
        self.add(1)
        with store.connect(self.path, write=True) as db:
            db.execute('UPDATE subjects SET active=0')
        with self.assertRaises(ValueError):
            self.recorder.flush()
        self.recorder.discard()
        self.assertEqual(self.runs()[0].times.count, 1)

    def test_pause_between_initial_validation_and_write_is_rechecked(self):
        from location_ledger import stay_recorder
        real = stay_recorder.source_id
        def pause_before_write(db, name):
            result = real(db, name)
            db.execute('UPDATE subjects SET active=0')
            return result
        with patch.object(stay_recorder, 'source_id', side_effect=pause_before_write):
            with self.assertRaisesRegex(ValueError, 'paused'):
                self.add()
        self.assertEqual(self.runs(), [])

    def test_external_change_is_not_overwritten(self):
        self.add()
        self.add(1)
        with store.connect(self.path, write=True) as db:
            db.execute('DELETE FROM samples')
        with self.assertRaisesRegex(ValueError, 'changed outside'):
            self.recorder.flush()
        self.assertEqual(self.runs(), [])

    def test_concurrent_newer_import_cannot_be_covered_or_overwritten(self):
        self.add()
        with store.connect(self.path, write=True) as db:
            store.ingest(db, 'participant', point(200, north=500), received_at=BASE+202)
        for offset, north in ((30, 0), (200, 100)):
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, 'changed outside'):
                self.add(offset, north=north)
        runs = self.runs()
        self.assertEqual([r.times.count for r in runs], [1, 1])
        self.assertGreater(runs[-1].lat_e6, 40004000)

    def test_background_checkpoint_flushes_when_no_new_report_arrives(self):
        self.add()
        self.add(1)
        self.recorder.last_checkpoint -= 31
        self.assertEqual(self.recorder.checkpoint()['updated'], 1)
        self.assertEqual(self.runs()[0].times.last, BASE+1)

    def test_profile_preserves_hourly_counts_and_dst(self):
        for timestamp in ('2025-11-02T05:00:00Z', '2025-11-02T05:30:00Z', '2025-11-02T06:00:00Z', '2025-11-02T06:30:00Z'):
            stamp = store.epoch(timestamp)
            with store.connect(self.path, write=True) as db:
                store.ingest(db, 'participant', point(observed_at=stamp), received_at=stamp)
        maintenance.optimize(self.path, 'participant', policy=StayPolicy(gap_seconds=3600), apply=True)
        with store.connect(self.path) as db:
            result = weekly_profile(db, 'participant', '2025-11-02T05:15:00Z', '2025-11-02T06:31:00Z', timezone_name='America/New_York')
        self.assertEqual(result['sample_count'], 3)
        self.assertEqual(len(result['cells']), 1)
        self.assertEqual(result['cells'][0]['hour'], 1)
        self.assertEqual(result['cells'][0]['dates_with_any_observation'], 1)

    def test_backup_and_restore_preserve_aggregate_counts_and_evidence(self):
        for second in (0, 30, 60):
            self.add(second)
        snapshot = Path(self.temp.name)/'backup.sqlite'
        result = maintenance.backup(self.path, snapshot)
        self.assertEqual((result['samples'], result['stored_rows']), (3, 1))
        with store.connect(snapshot) as db:
            self.assertEqual(store.report(db, 'participant', BASE, BASE+100)['sample_count'], 3)

    def test_interval_query_uses_primary_key_without_full_scan(self):
        self.add()
        self.add(300)
        with store.connect(self.path) as db:
            plans = []
            for sql, args in (
                ('SELECT * FROM samples WHERE subject_id=? AND observed_at<? ORDER BY observed_at DESC LIMIT 1', (1, BASE+1)),
                ('SELECT * FROM samples WHERE subject_id=? AND observed_at>=? AND observed_at<? ORDER BY observed_at', (1, BASE, BASE+500))):
                plans.extend(r['detail'] for r in db.execute('EXPLAIN QUERY PLAN '+sql, args))
            self.assertTrue(all('SEARCH samples USING PRIMARY KEY' in p for p in plans), plans)
            self.assertEqual(len(list(range_rows(db, 1, BASE+1, BASE+400))), 1)

    def test_report_uses_consistent_snapshot_while_live_writer_commits(self):
        self.add()
        with store.connect(self.path) as reader:
            self.assertEqual(store.statistics(reader)['samples'], 1)
            with store.connect(self.path, write=True) as writer:
                store.ingest(writer, 'participant', point(30), received_at=BASE+32)
            self.assertEqual(store.report(reader, 'participant', BASE, BASE+100)['sample_count'], 1)
        self.assertEqual(self.report()['sample_count'], 2)


class TimingTests(unittest.TestCase):
    def test_random_timing_roundtrip_clipping_and_compression(self):
        rng = random.Random(7)
        for _ in range(60):
            raw = [BASE]
            times = Times(BASE)
            for _ in range(100):
                raw.append(raw[-1]+rng.randint(1, 400))
                times = times.append(raw[-1])
            self.assertEqual(expanded(times), raw)
            low, high = sorted(rng.sample(raw, 2))
            clipped = times.clip(low+1, high)
            expected = [x for x in raw if low+1 <= x < high]
            self.assertEqual(expanded(clipped) if clipped else [], expected)

    def test_bad_encoded_payloads_and_decompression_bombs_fail(self):
        base = dict(subject_id=1, observed_at=BASE, received_at=BASE, lat_e6=40000000,
                    lon_e6=-75000000, accuracy_dm=50, source_id=1, span_seconds=1, fix_count=2)
        for payload in (b'', b'\x03', b'\x01\x80', b'\x02'+zlib.compress(b'\0'*20000)):
            with self.subTest(payload_size=len(payload)), self.assertRaises(ValueError):
                Run.from_row(dict(base, detail=payload))


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'v1.sqlite'
        # A literal v1 fixture verifies compatibility rather than recreating the
        # current schema through the implementation under test.
        with closing(sqlite3.connect(self.path)) as db:
            db.executescript('''CREATE TABLE subjects(id INTEGER PRIMARY KEY,alias TEXT UNIQUE,consent_at INTEGER,active INTEGER);
                CREATE TABLE sources(id INTEGER PRIMARY KEY,name TEXT UNIQUE);
                CREATE TABLE samples(subject_id INTEGER REFERENCES subjects(id),observed_at INTEGER,received_at INTEGER,
                    lat_e6 INTEGER,lon_e6 INTEGER,accuracy_dm INTEGER,source_id INTEGER REFERENCES sources(id),
                    PRIMARY KEY(subject_id,observed_at)) WITHOUT ROWID;
                CREATE TABLE places(id INTEGER PRIMARY KEY,subject_id INTEGER,label TEXT,lat_e6 INTEGER,lon_e6 INTEGER,radius_m INTEGER);
                INSERT INTO subjects VALUES(1,'participant',1760000000,1);
                INSERT INTO subjects VALUES(2,'other',1760000000,0);
                INSERT INTO sources VALUES(1,'synthetic'); PRAGMA user_version=1;''')
            for offset in (0, 300, 600, 900, 3600, 3900):
                db.execute('INSERT INTO samples VALUES(?,?,?,?,?,?,?)', (1, BASE+offset, BASE+offset+2, 40000000, -75000000, 50, 1))
            db.execute('INSERT INTO samples VALUES(?,?,?,?,?,?,?)', (2, BASE, BASE, 41000000, -74000000, 50, 1))
            db.commit()

    def test_preview_is_readonly_and_upgrade_preserves_evidence_and_other_participant(self):
        digest = hashlib.sha256(self.path.read_bytes()).digest()
        preview = maintenance.optimize(self.path, 'participant')
        self.assertEqual((preview['rows_before'], preview['rows_after']), (6, 2))
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), digest)
        result = maintenance.optimize(self.path, 'participant', apply=True)
        with store.connect(self.path) as db:
            self.assertEqual(store.statistics(db)['samples'], 7)
            self.assertEqual(store.statistics(db)['stored_rows'], 3)
            self.assertFalse(store.subject(db, 'other')['active'])
            self.assertEqual(store.report(db, 'participant', BASE, BASE+4000)['sample_count'], 6)
        with store.connect(result['backup_created']) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 1)
            self.assertEqual(store.statistics(db)['stored_rows'], 7)
        second = maintenance.optimize(self.path, 'participant')
        self.assertEqual(second['rows_removed'], 0)

    def test_failure_rolls_back_schema_and_history(self):
        real = maintenance.joined_runs
        calls = 0
        def fail_during_write(*args):
            nonlocal calls
            calls += 1
            yield next(real(*args))
            if calls == 2:
                raise ValueError('Synthetic failure')
            yield from list(real(*args))[1:]
        with patch.object(maintenance, 'joined_runs', side_effect=fail_during_write), self.assertRaisesRegex(ValueError, 'Synthetic failure'):
            maintenance.optimize(self.path, 'participant', apply=True)
        with store.connect(self.path) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 1)
            self.assertEqual(store.statistics(db)['stored_rows'], 7)
