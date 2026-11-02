import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from location_ledger import store

BASE = store.epoch("2026-01-05T12:00:00Z")


def point(offset=0, **changes):
    result = {"observed_at": BASE + offset, "latitude": 40.0, "longitude": -75.0,
              "accuracy_m": 10, "source": "synthetic"}
    result.update(changes)
    return result


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "ledger.db"
        store.initialize(self.path)
        with store.connect(self.path, write=True) as db:
            store.register(db, "participant")
            store.add_place(db, "participant", "Label A", 40, -75, 100)

    def tearDown(self):
        self.temp.cleanup()

    def insert(self, *points):
        with store.connect(self.path, write=True) as db:
            for item in points:
                store.ingest(db, "participant", item, received_at=BASE + 86400)

    def report(self):
        with store.connect(self.path) as db:
            return store.report(db, "participant", BASE, BASE + 86400, max_gap=600)

    def test_repolling_stale_fix_does_not_create_history(self):
        with store.connect(self.path, write=True) as db:
            self.assertTrue(store.ingest(db, "participant", point(), received_at=BASE + 60))
            for lag in (120, 300, 600):
                self.assertFalse(store.ingest(db, "participant", point(), received_at=BASE + lag))
        result = self.report()
        self.assertEqual(result["sample_count"], 1)
        self.assertEqual(result["spans"][0]["observed_span_seconds"], 0)
        self.assertEqual(result["last_receipt_at"], store.iso(BASE + 60))

    def test_gap_splits_same_place(self):
        self.insert(point(), point(300), point(3600), point(3900))
        result = self.report()
        self.assertEqual(len(result["spans"]), 2)
        self.assertEqual(result["gaps"][0]["seconds"], 3300)
        self.assertEqual(sum(s["observed_span_seconds"] for s in result["spans"]), 600)

    def test_uncertain_fix_cannot_bridge_two_stays(self):
        self.insert(point(), point(300), point(600, accuracy_m=300), point(900))
        spans = self.report()["spans"]
        self.assertEqual([s["place"] for s in spans], ["Label A", None, "Label A"])
        self.assertEqual(spans[1]["quality"], "low_accuracy")

    def test_accuracy_circle_crossing_boundary_is_not_assigned(self):
        self.insert(point(0, latitude=40.0008, accuracy_m=30))
        self.assertIsNone(self.report()["spans"][0]["place"])

    def test_late_backfill_sorts_by_fix_time(self):
        self.insert(point(600), point(), point(300))
        span = self.report()["spans"][0]
        self.assertEqual(span["first_observed_at"], store.iso(BASE))
        self.assertEqual(span["last_observed_at"], store.iso(BASE + 600))

    def test_conflicts_and_future_fixes_rejected(self):
        self.insert(point())
        with store.connect(self.path, write=True) as db:
            with self.assertRaises(ValueError):
                store.ingest(db, "participant", point(latitude=41), received_at=BASE + 10)
            with self.assertRaises(ValueError):
                store.ingest(db, "participant", point(10000), received_at=BASE)

    def test_invalid_numbers_and_timestamp_units(self):
        for changes in ({"latitude": float("nan")}, {"longitude": 181},
                        {"accuracy_m": -1}, {"latitude": True},
                        {"observed_at": BASE * 1000}, {"observed_at": "2026-01-05T12:00:00"}):
            with self.subTest(changes=changes), store.connect(self.path, write=True) as db:
                with self.assertRaises(ValueError):
                    store.ingest(db, "participant", point(**changes), received_at=BASE + 60)

    def test_registration_and_pause(self):
        with store.connect(self.path, write=True) as db:
            store.register(db, "other")
            self.assertTrue(store.subject(db, "other", require_active=True)["active"])
            db.execute("UPDATE subjects SET active=0 WHERE alias='participant'")
            with self.assertRaises(ValueError):
                store.ingest(db, "participant", point(), received_at=BASE)

    def test_cli_register_and_resume_need_no_acknowledgement_and_keep_history(self):
        self.insert(point())
        def command(*args):
            return subprocess.run([sys.executable, "-m", "location_ledger", "--db", str(self.path), *args],
                                  capture_output=True, text=True)
        registered = command("register", "new-participant")
        self.assertEqual(registered.returncode, 0, registered.stderr)
        self.assertEqual(command("pause", "participant").returncode, 0)
        with store.connect(self.path, write=True) as db:
            with self.assertRaisesRegex(ValueError, "paused"):
                store.ingest(db, "participant", point(300), received_at=BASE + 300)
        resumed = command("resume", "participant")
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertEqual(self.report()["sample_count"], 1)
        with store.connect(self.path) as db:
            self.assertTrue(store.subject(db, "participant", require_active=True)["active"])
            self.assertIsInstance(store.subject(db, "new-participant")["consent_at"], int)

    def test_obsolete_cli_flag_is_optional_and_hidden_for_old_scripts(self):
        base = [sys.executable, "-m", "location_ledger", "--db", str(self.path)]
        result = subprocess.run(base + ["register", "legacy-script", "--consent-to-history-and-analysis"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("register", "resume"):
            help_result = subprocess.run(base + [name, "--help"], capture_output=True, text=True)
            self.assertEqual(help_result.returncode, 0)
            self.assertNotIn("consent", help_result.stdout)

    def test_readonly_query_cannot_modify_database(self):
        with store.connect(self.path) as db:
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("DELETE FROM subjects")

    def test_report_window_is_half_open(self):
        self.insert(point(), point(300), point(600))
        with store.connect(self.path) as db:
            result = store.report(db, "participant", BASE, BASE + 600)
        self.assertEqual(result["sample_count"], 2)

    def test_report_does_not_return_coordinates(self):
        self.insert(point())
        output = json.dumps(self.report())
        self.assertNotIn("lat_e6", output)
        self.assertNotIn("longitude", output)
        self.assertNotIn("-75", output)

    def test_database_creation_never_overwrites_existing_history(self):
        self.insert(point())
        with self.assertRaises(FileExistsError):
            store.initialize(self.path)
        self.assertEqual(self.report()["sample_count"], 1)

    def test_cli_invalid_import_is_atomic(self):
        path = Path(self.temp.name) / "import.jsonl"
        path.write_text(json.dumps(point()) + "\n" + json.dumps(point(300, latitude=999)) + "\n")
        result = subprocess.run([sys.executable, "-m", "location_ledger", "--db", str(self.path),
                                 "import", "participant", str(path)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("line 2", result.stderr)
        self.assertEqual(self.report()["sample_count"], 0)


if __name__ == "__main__":
    unittest.main()
