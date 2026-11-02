import sqlite3
import tempfile
import unittest
from pathlib import Path

from location_ledger import maintenance, store

BASE = store.epoch("2026-01-05T12:00:00Z")


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.path = self.root / "history.sqlite"
        store.initialize(self.path)
        with store.connect(self.path, write=True) as db:
            for alias in ("participant", "other"):
                store.register(db, alias)
                store.add_place(db, alias, "Synthetic label", 40, -75, 100)
                for offset in (0, 300, 600):
                    store.ingest(db, alias, {"observed_at": BASE + offset, "latitude": 40, "longitude": -75,
                                 "accuracy_m": 10, "source": "synthetic"}, received_at=BASE + 1000)

    def tearDown(self):
        self.tmp.cleanup()

    def test_backup_and_restore_include_committed_wal_and_preserve_pause(self):
        destination = self.root / "backup.sqlite"
        with store.connect(self.path, write=True) as writer:
            writer.execute("PRAGMA wal_autocheckpoint=0")
            writer.execute("UPDATE subjects SET active=0 WHERE alias='participant'")
            writer.commit()
            self.assertGreater(Path(str(self.path) + "-wal").stat().st_size, 0)
            result = maintenance.backup(self.path, destination)
            self.assertEqual(result["samples"], 6)
        restored = self.root / "restored.sqlite"
        maintenance.backup(destination, restored)
        with store.connect(restored) as db:
            self.assertEqual(store.statistics(db)["samples"], 6)
            self.assertFalse(store.subject(db, "participant")["active"])
            self.assertEqual(db.execute("SELECT count(*) FROM places").fetchone()[0], 2)
        self.assertEqual(list(self.root.glob("*.tmp")), [])

    def test_backup_never_overwrites_or_creates_missing_source(self):
        destination = self.root / "existing.sqlite"
        destination.write_bytes(b"existing file")
        with self.assertRaises(FileExistsError):
            maintenance.backup(self.path, destination)
        self.assertEqual(destination.read_bytes(), b"existing file")
        missing, output = self.root / "missing.sqlite", self.root / "failed.sqlite"
        with self.assertRaises(sqlite3.Error):
            maintenance.backup(missing, output)
        self.assertFalse(missing.exists())
        self.assertFalse(output.exists())

    def test_retention_is_readonly_by_default_and_preserves_cutoff_and_other_person(self):
        with store.connect(self.path) as db:
            result = maintenance.retain(db, "participant", BASE + 300)
            self.assertEqual(result["eligible_samples"], 1)
            self.assertEqual(store.statistics(db)["samples"], 6)
        with store.connect(self.path, write=True) as db:
            maintenance.retain(db, "participant", BASE + 300, apply=True)
        with store.connect(self.path) as db:
            sid = store.subject(db, "participant")["id"]
            self.assertEqual(db.execute("SELECT observed_at FROM samples WHERE subject_id=? ORDER BY observed_at", (sid,)).fetchall()[0][0], BASE + 300)
            self.assertEqual(store.statistics(db)["samples"], 5)

    def test_rotation_only_removes_old_collector_snapshots(self):
        directory = self.root / "backups"
        directory.mkdir()
        for offset in range(9):
            (directory / f"ledger-{BASE + offset}-01234567.sqlite").write_bytes(b"synthetic snapshot")
        unrelated = directory / "manual-backup.sqlite"
        unrelated.write_bytes(b"keep")
        result = maintenance.rotate_backups(directory, keep=7)
        self.assertEqual(result, {"backups_removed": 2, "backups_retained": 7})
        self.assertFalse((directory / f"ledger-{BASE}-01234567.sqlite").exists())
        self.assertTrue((directory / f"ledger-{BASE + 8}-01234567.sqlite").exists())
        self.assertEqual(unrelated.read_bytes(), b"keep")
        with self.assertRaises(ValueError):
            maintenance.rotate_backups(directory, keep=0)

    def test_forget_blocks_recollection_and_keeps_other_history(self):
        with store.connect(self.path) as db:
            self.assertFalse(maintenance.forget(db, "participant")["applied"])
        with store.connect(self.path, write=True) as db:
            maintenance.forget(db, "participant", apply=True)
        with store.connect(self.path, write=True) as db:
            self.assertEqual(store.statistics(db)["samples"], 3)
            self.assertEqual(db.execute("SELECT count(*) FROM places").fetchone()[0], 1)
            with self.assertRaises(ValueError):
                store.ingest(db, "participant", {})
            with self.assertRaises(sqlite3.IntegrityError):
                store.register(db, "participant")
        result = maintenance.compact(self.path)
        self.assertTrue(result["wal_checkpoint_complete"])
