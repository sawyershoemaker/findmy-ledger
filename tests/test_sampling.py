import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from location_ledger import store
from location_ledger.sampling import AdaptiveRecorder, AdaptiveSampler, SamplingPolicy

BASE = store.epoch("2026-01-05T12:00:00Z")


def point(seconds=0, *, north_m=0, **changes):
    item = {"observed_at": BASE + seconds, "latitude": 40 + north_m / 111195,
            "longitude": -75.0, "accuracy_m": 5, "source": "synthetic-live"}
    item.update(changes)
    return item


class SamplingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "ledger.sqlite"
        store.initialize(self.path)
        with store.connect(self.path, write=True) as db:
            store.register(db, "participant")
        self.recorder = AdaptiveRecorder(self.path, "participant")

    def tearDown(self):
        self.temp.cleanup()

    def add(self, seconds=0, **changes):
        return self.recorder.accept(point(seconds, **changes), received_at=BASE + seconds + 2)

    def rows(self):
        with store.connect(self.path) as db:
            return db.execute("SELECT * FROM samples ORDER BY observed_at").fetchall()

    def test_hour_of_stationary_stream_keeps_five_minute_evidence(self):
        # Exercise the sampler at 1 Hz, without making thousands of fsyncs.
        sampler = AdaptiveSampler()
        kept = []
        for second in range(3601):
            kept.extend(sampler.accept(point(second, north_m=(second % 5) - 2),
                                       received_at=BASE + second + 2).fixes)
        kept.extend(sampler.flush().fixes)
        self.assertEqual([f.observed_at - BASE for f in kept], list(range(0, 3601, 300)))
        self.assertEqual(len(kept), 13)

    def test_slow_movement_is_measured_from_retained_anchor(self):
        self.add()
        for second in range(1, 10):
            self.assertEqual(self.add(second, north_m=second)["reason"], "coalesced")
        result = self.add(11, north_m=11)
        self.assertEqual(result["reason"], "movement_change")
        self.assertEqual([r["observed_at"] - BASE for r in self.rows()], [0, 9, 11])

    def test_jitter_inside_accuracy_circles_does_not_imply_movement(self):
        self.add(0, accuracy_m=50)
        for second in range(1, 20):
            self.assertTrue(self.add(second, north_m=40 * (-1) ** second, accuracy_m=50)["coalesced"])
        self.assertEqual(len(self.rows()), 1)

    def test_quality_transition_keeps_endpoints_and_uncertainty(self):
        self.add()
        self.add(1)
        self.assertEqual(self.add(2, accuracy_m=300)["reason"], "accuracy_changed")
        self.add(3, accuracy_m=300)
        self.assertEqual(self.add(4)["reason"], "accuracy_changed")
        self.assertEqual([r["accuracy_dm"] for r in self.rows()], [50, 50, 3000, 3000, 50])
        with store.connect(self.path) as db:
            report = store.report(db, "participant", BASE, BASE + 100)
        self.assertIn("low_accuracy", [span["quality"] for span in report["spans"]])

    def test_gap_and_orderly_close_keep_original_endpoints(self):
        self.add()
        self.add(59)
        self.assertEqual(self.add(200)["reason"], "gap_boundary")
        self.add(210)
        self.recorder.flush()
        rows = self.rows()
        self.assertEqual([r["observed_at"] - BASE for r in rows], [0, 59, 200, 210])
        self.assertEqual([r["received_at"] - r["observed_at"] for r in rows], [2] * 4)
        self.assertEqual(self.recorder.flush()["inserted"], 0)

    def test_receipt_outage_preserves_boundary_even_for_delayed_source_fixes(self):
        self.add()
        self.add(1)
        result = self.recorder.accept(point(2), received_at=BASE + 200)
        self.assertEqual(result["reason"], "gap_boundary")
        self.assertEqual(len(self.rows()), 3)

    def test_replays_do_not_extend_stationary_history(self):
        self.add()
        for receipt in (BASE + 100, BASE + 300, BASE + 600):
            self.assertEqual(self.recorder.accept(point(), received_at=receipt)["duplicates"], 1)
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.rows()[0]["received_at"], BASE + 2)

    def test_pending_timestamp_conflict_fails_without_advancing_state(self):
        self.add()
        self.add(1)
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            self.add(1, north_m=50)
        self.recorder.flush()
        self.assertEqual(self.rows()[-1]["lat_e6"], 40000000)

    def test_late_backfill_does_not_move_anchor_backwards(self):
        self.add(100)
        self.add(110)
        self.assertEqual(self.add(50, north_m=100)["reason"], "out_of_order")
        self.assertEqual(self.add(111)["reason"], "coalesced")
        self.recorder.flush()
        self.assertEqual([r["observed_at"] - BASE for r in self.rows()], [50, 100, 111])

    def test_restart_reads_last_committed_point_and_catches_motion(self):
        self.add()
        self.add(1)
        self.recorder = AdaptiveRecorder(self.path, "participant")
        self.assertEqual(self.add(2, north_m=30)["reason"], "movement_change")
        self.assertEqual([r["observed_at"] - BASE for r in self.rows()], [0, 2])

    def test_pause_blocks_both_new_fixes_and_pending_flush(self):
        self.add()
        self.add(1)
        with store.connect(self.path, write=True) as db:
            db.execute("UPDATE subjects SET active=0")
        with self.assertRaisesRegex(ValueError, "paused"):
            self.add(2)
        with self.assertRaisesRegex(ValueError, "paused"):
            self.recorder.flush()
        self.recorder.discard()
        self.assertEqual(len(self.rows()), 1)

    def test_dateline_crossing_uses_geodesic_distance(self):
        self.add(0, latitude=0, longitude=179.99999)
        self.assertEqual(self.add(1, latitude=0, longitude=-179.99999)["reason"], "coalesced")
        self.assertEqual(self.add(2, latitude=0, longitude=-179.999)["reason"], "movement_change")

    def test_invalid_dropped_observation_is_still_rejected(self):
        self.add()
        for changes in ({"accuracy_m": float("nan")}, {"latitude": True}, {"observed_at": BASE * 1000}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.add(1, **changes)
        self.assertEqual(self.add(2)["reason"], "coalesced")

    def test_sampling_policy_rejects_nonfinite_or_invalid_thresholds(self):
        for changes in ({"movement_m": float("nan")}, {"stationary_seconds": True},
                        {"gap_seconds": 0}, {"max_accuracy_m": float("inf")}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                SamplingPolicy(**changes)

    def test_adaptive_import_is_atomic_and_keeps_final_endpoint(self):
        fixture = Path(self.temp.name) / "stream.jsonl"
        fixture.write_text("\n".join(json.dumps(point(s)) for s in range(602)), encoding="utf-8")
        command = [sys.executable, "-m", "location_ledger", "--db", str(self.path), "import",
                   "participant", str(fixture), "--adaptive"]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["inserted"], 4)
        self.assertEqual([r["observed_at"] - BASE for r in self.rows()], [0, 300, 600, 601])
        fixture.write_text(json.dumps(point(800, north_m=100)) + '\n{"bad": true}\n', encoding="utf-8")
        failed = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(failed.returncode, 2)
        self.assertEqual(len(self.rows()), 4)
