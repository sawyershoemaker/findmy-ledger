import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from research.recovery import storage_failure
from research.collector import collector_lock, write_status
from research.collector_watchdog import check, decide, WindowsTask


class RecoveryClassificationTests(unittest.TestCase):
    def test_only_known_temporary_storage_codes_recover(self):
        for code in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED, sqlite3.SQLITE_FULL,
                     sqlite3.SQLITE_IOERR, sqlite3.SQLITE_CANTOPEN, sqlite3.SQLITE_READONLY):
            error = sqlite3.OperationalError("private detail")
            error.sqlite_errorcode = code
            info = storage_failure(error)
            self.assertTrue(info["automatic_recovery"])
            self.assertNotIn("private", json.dumps(info))
        for code in (sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB, sqlite3.SQLITE_CONSTRAINT):
            error = sqlite3.DatabaseError("private detail")
            error.sqlite_errorcode = code
            self.assertFalse(storage_failure(error)["automatic_recovery"])
        self.assertFalse(storage_failure(ValueError("invalid history"))["automatic_recovery"])


class WatchdogPolicyTests(unittest.TestCase):
    def setUp(self):
        self.task = {"state": "Ready", "last_run_unix": 100}
        self.status = {"state": "collecting", "heartbeat_unix": 990, "source_observed_unix": 200}

    def decide(self, **kwargs):
        return decide(self.task, self.status, kwargs.pop("saved", {}), now=1000, **kwargs)

    def test_clean_unexpected_exit_recovers_even_without_nonzero_exit_code(self):
        self.assertEqual(self.decide(), ("start", "worker_exited_unexpectedly"))

    def test_auth_validation_and_intentional_stops_are_not_restarted(self):
        for state, reason in (("needs_attention", "authentication_or_protocol_requires_attention"),
                              ("paused", "sharing_relationship_unavailable"), ("stopped", "local_stop"),
                              ("stopped", "bounded_run_finished")):
            self.status.update(state=state, reason=reason)
            self.assertEqual(self.decide()[0], "none")
        self.status.update(state="needs_attention", automatic_recovery=True, reason="history_write_failed")
        self.assertEqual(self.decide()[0], "start")
        self.assertEqual(self.decide(manual_stop=True)[0], "none")

    def test_hang_gets_graceful_request_then_force_stop(self):
        self.task["state"] = "Running"
        self.status["heartbeat_unix"] = 100
        self.assertEqual(self.decide()[0], "request_stop")
        self.assertEqual(self.decide(saved={"restart_requested_unix": 990})[0], "none")
        self.assertEqual(self.decide(saved={"restart_requested_unix": 970})[0], "force_stop")

    def test_old_location_alone_does_not_restart_responsive_worker(self):
        self.task["state"] = "Running"
        self.assertEqual(self.decide(), ("none", "worker_responsive"))

    def test_replacement_has_startup_grace_and_old_requests_do_not_force_kill(self):
        self.task.update(state="Running", last_run_unix=950)
        self.status["heartbeat_unix"] = 100
        self.assertEqual(self.decide()[1], "worker_starting")
        self.task["last_run_unix"] = 700
        self.assertEqual(self.decide(saved={"restart_requested_unix": 600})[0], "request_stop")

    def test_disabled_tasks_paused_participants_and_cooldowns(self):
        self.task["state"] = "Disabled"
        self.assertEqual(self.decide()[0], "none")
        self.task["state"] = "Running"
        self.assertEqual(self.decide(participant_active=False)[0], "stop")
        self.task["state"] = "Ready"
        self.assertEqual(self.decide(participant_active=False)[0], "none")
        self.assertEqual(self.decide(cooldown_until=1100)[1], "recovery_backoff")
        self.assertEqual(self.decide(saved={"next_restart_unix": 1100})[1], "recovery_backoff")
        self.status["next_connect_unix"] = 1100
        self.assertEqual(self.decide()[1], "recovery_backoff")


class TaskFixture:
    def __init__(self):
        self.state = "Ready"
        self.starts = self.stops = 0
    def query(self):
        return {"state": self.state, "last_run_unix": 100}
    def start(self):
        self.starts += 1
    def stop(self):
        self.stops += 1
        self.state = "Ready"


class WatchdogIntegrationTests(unittest.TestCase):
    def test_default_participant_check_uses_pause_state_without_acknowledgement(self):
        from location_ledger import store
        database = self.root / "history.sqlite"
        store.initialize(database)
        with store.connect(database, write=True) as db:
            store.register(db, "synthetic")
        with patch("research.collector_watchdog.load", return_value={"alias": "synthetic"}):
            check(self.root, database, self.control, now=1000, bootstrap_check=lambda: {"ready": True})
            self.assertEqual(self.control.starts, 1)
            with store.connect(database, write=True) as db:
                db.execute("UPDATE subjects SET active=0")
            self.control.state = "Running"
            check(self.root, database, self.control, now=1060, bootstrap_check=lambda: {"ready": True})
            self.assertEqual(self.control.stops, 1)
            self.assertEqual(self.control.starts, 1)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.control = TaskFixture()
        self.status = {"state": "collecting", "heartbeat_unix": 900}
        write_status(self.root/"collector-status.json", self.status)

    def check(self, now=1000, **kwargs):
        return check(self.root, self.root/"unused.sqlite", self.control, now=now,
                     participant_check=kwargs.pop("participant_check", lambda: True),
                     bootstrap_check=kwargs.pop("bootstrap_check", lambda: {"ready": True}), **kwargs)

    def test_restart_budget_survives_new_check_and_caps_backoff(self):
        first = self.check()
        self.assertEqual((first["restart_count"], first["next_restart_unix"]), (1, 1030))
        self.check(now=1001)
        self.assertEqual(self.control.starts, 1)
        now = 1031
        for _ in range(12):
            called_at = now
            output = self.check(now=now)
            self.assertLessEqual(output["next_restart_unix"] - now, 900)
            now = output["next_restart_unix"] + 1
        self.assertEqual(output["next_restart_unix"] - called_at, 900)

    def test_hang_recovery_is_two_phase_and_cleans_only_restart_request(self):
        self.control.state = "Running"
        first = self.check(now=1300)
        self.assertEqual(first["action"], "request_stop")
        self.assertTrue((self.root/"live-restart.request").exists())
        self.check(now=1360)
        self.assertEqual(self.control.stops, 1)
        self.assertEqual(self.control.starts, 0)
        self.check(now=1420)
        self.assertEqual(self.control.starts, 1)
        self.assertFalse((self.root/"live-restart.request").exists())

    def test_manual_marker_and_bootstrap_gate_prevent_restart(self):
        self.check(bootstrap_check=lambda: {"ready": False})
        self.assertEqual(self.control.starts, 0)
        (self.root/"live-stop.request").touch()
        self.check()
        self.assertEqual(self.control.starts, 0)
        self.assertTrue((self.root/"live-stop.request").exists())

    def test_paused_participant_stops_hung_task_without_restarting(self):
        self.control.state = "Running"
        self.check(participant_check=lambda: False)
        self.assertEqual(self.control.stops, 1)
        self.check(now=1060, participant_check=lambda: False)
        self.assertEqual(self.control.starts, 0)

    def test_unrelated_task_cannot_be_controlled(self):
        with self.assertRaises(ValueError):
            WindowsTask(self.root, "AnotherTask; Invoke-Anything")

    def test_foreground_collector_lock_prevents_duplicate_start(self):
        with collector_lock(self.root/"collector.lock"):
            output = self.check()
        self.assertEqual(output["reason"], "collector_already_running")
        self.assertEqual(self.control.starts, 0)

    def test_corrupt_status_fails_closed_instead_of_ignoring_possible_auth_stop(self):
        (self.root/"collector-status.json").write_text("not-json")
        with self.assertRaises(ValueError):
            self.check()
        self.assertEqual(self.control.starts, 0)


if __name__ == "__main__":
    unittest.main()
