import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from research.collector import collector_lock, prerequisite, run, run_until_stopped, schedule, serve, write_status


class CollectorTests(unittest.TestCase):
    def test_no_key_means_no_credentials_or_network_loaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("research.collector.load") as loader:
                result = prerequisite(root, root / "history.sqlite")
            self.assertFalse(result["ready"])
            loader.assert_not_called()
            self.assertIn("people-key.dpapi", result["missing_files"])
            self.assertIn("ids.dpapi", result["missing_files"])

    def test_rate_limit_and_missing_updates_slow_collection_without_fabrication(self):
        pending = schedule({"seconds_remaining": 8000}, 3, 300, now=1000)
        self.assertEqual(pending["next_poll_unix"], 9000)
        throttled = schedule({"searchparty_response": {"http_status": 429, "retry_after_seconds": 9000}}, 0, 300, now=1000)
        self.assertEqual(throttled["next_poll_unix"], 10000)
        unavailable = schedule({"searchparty_response": {"http_status": 503}}, 0, 300, now=1000)
        self.assertEqual(unavailable["next_poll_unix"], 3700)
        fresh = schedule({"success": True, "fresh_report_received": True}, 12, 300, now=1000)
        self.assertEqual(fresh["failures"], 0)
        self.assertEqual(fresh["next_poll_unix"], 1300)
        stopped = schedule({"stop_reason": "sharing_relationship_unavailable"}, 1, 300, now=1000)
        self.assertIsNone(stopped["next_poll_unix"])
        delayed = schedule({"success": True, "delayed_report_received": True, "new_observation": True}, 8, 300, now=1000)
        self.assertEqual(delayed["reason"], "delayed_location_recorded")
        self.assertEqual(delayed["next_poll_unix"], 1300)
        duplicate = schedule({"success": True, "delayed_report_received": True, "new_observation": False}, 8, 300, now=1000)
        self.assertEqual(duplicate["reason"], "no_fresh_location")
        self.assertEqual(duplicate["next_poll_unix"], 4600)

    def test_restart_honors_saved_deadline_and_never_catches_up_with_a_burst(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clock = [1000.0]
            polls = []
            write_status(root / "collector-status.json", {"next_poll_unix": 1030, "failures": 2})
            async def fake_sleep(seconds):
                clock[0] += seconds
            async def fake_poll(*args):
                polls.append(clock[0])
                return {"success": True, "fresh_report_received": True, "new_observation": True}
            with patch("research.collector.prerequisite", return_value={"ready": True}), \
                 patch("research.collector.load", return_value={"alias": "synthetic"}), \
                 patch("research.collector.auth_cooldown.active", return_value=None), \
                 patch("research.collector.searchparty_backoff.active", return_value=None), \
                 patch("research.collector.time.time", side_effect=lambda: clock[0]), \
                 patch("research.collector.asyncio.sleep", side_effect=fake_sleep), \
                 patch("research.collector.poll", side_effect=fake_poll):
                result = asyncio.run(run(root, root / "history.sqlite", max_polls=2))
            self.assertEqual(polls, [1030, 1330])
            self.assertEqual(result["next_poll_unix"], 1630)
            self.assertEqual(json.loads((root / "collector-status.json").read_text())["failures"], 0)

    def test_explicit_local_503_schedule_is_gradual_and_retains_429_deadlines(self):
        failure = {"searchparty_response": {"http_status": 503, "retry_after_seconds": 2400}}
        first = schedule(failure, 0, 300, now=1000, retry_503_locally=True)
        second = schedule(failure, 1, 300, now=1000, retry_503_locally=True)
        self.assertEqual(first["next_poll_unix"], 1300)
        self.assertEqual(second["next_poll_unix"], 1600)
        failure["searchparty_response"]["http_status"] = 429
        self.assertEqual(schedule(failure, 0, 300, now=1000, retry_503_locally=True)["next_poll_unix"], 3400)

    def test_pause_stops_before_a_network_poll(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("research.collector.prerequisite", return_value={"ready": False, "reason": "participant_paused"}), \
                 patch("research.collector.poll", new_callable=AsyncMock) as poller:
                result = asyncio.run(run(root, root / "history.sqlite", max_polls=1))
            poller.assert_not_awaited()
            self.assertEqual(result["reason"], "participant_paused")

    def test_poll_waits_for_verified_push_receiver(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ready = asyncio.Event()
            waits = []
            async def connected(seconds):
                waits.append(seconds)
                ready.set()
            async def fetch(*args):
                self.assertTrue(ready.is_set())
                return {"success": True, "fresh_report_received": True}
            with patch("research.collector.prerequisite", return_value={"ready": True}), \
                 patch("research.collector.load", return_value={"alias": "synthetic"}), \
                 patch("research.collector.asyncio.sleep", side_effect=connected), \
                 patch("research.collector.poll", side_effect=fetch):
                result = asyncio.run(run(root, root / "history.sqlite", max_polls=1, receiver_ready=ready))
            self.assertEqual(waits, [1])
            self.assertTrue(result["success"])

    def test_cancellation_preserves_deadline_for_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_status(root / "collector-status.json", {"next_poll_unix": 2000, "failures": 4, "last_backup_unix": 900})
            async def cancelled(*args, **kwargs):
                raise asyncio.CancelledError()
            with patch("research.collector.run", side_effect=cancelled):
                with self.assertRaises(asyncio.CancelledError):
                    asyncio.run(run_until_stopped(root, root / "history.sqlite"))
            result = json.loads((root / "collector-status.json").read_text())
            self.assertEqual(result["next_poll_unix"], 2000)
            self.assertEqual(result["failures"], 4)
            self.assertEqual(result["last_backup_unix"], 900)
            self.assertEqual(result["state"], "stopped")

    def test_failed_backup_keeps_collection_deadline_and_reports_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = root / "history.sqlite"
            database.touch()
            with patch("research.collector.prerequisite", return_value={"ready": True}), \
                 patch("research.collector.load", return_value={"alias": "synthetic"}), \
                 patch("research.collector.auth_cooldown.active", return_value=None), \
                 patch("research.collector.searchparty_backoff.active", return_value=None), \
                 patch("research.collector.time.time", return_value=200000), \
                 patch("research.collector.poll", new_callable=AsyncMock, return_value={"success": True, "fresh_report_received": True}), \
                 patch("research.collector.maintenance.backup", side_effect=OSError("synthetic disk full")):
                result = asyncio.run(run(root, database, max_polls=1, backup_dir=root / "backups"))
            self.assertEqual(result["next_poll_unix"], 200300)
            self.assertEqual(result["maintenance_warning"], "retention_or_backup_failed")
            self.assertEqual(json.loads((root / "collector-status.json").read_text())["next_poll_unix"], 200300)

    def test_one_writer_lock_is_released_on_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "collector.lock"
            with self.assertRaises(ValueError):
                with collector_lock(lock):
                    with self.assertRaises((OSError, RuntimeError)):
                        with collector_lock(lock):
                            self.fail("second collector acquired the lock")
                    raise ValueError("synthetic interruption")
            with collector_lock(lock):
                pass

    def test_key_receiver_failure_stops_polling_and_keeps_saved_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_status(root / "collector-status.json", {"next_poll_unix": 2000, "success": True})
            stopped = []
            async def polling(*args, **kwargs):
                try:
                    await asyncio.Event().wait()
                finally:
                    stopped.append(True)
            with patch("research.collector.prerequisite", return_value={"ready": True}), \
                 patch("research.collector.run_until_stopped", side_effect=polling), \
                 patch("research.key_listener.run", new_callable=AsyncMock,
                       return_value={"state": "needs_attention", "reason": "sharing_relationship_unavailable"}):
                result = asyncio.run(serve(root, root / "history.sqlite"))
            self.assertEqual(stopped, [True])
            self.assertEqual(result["next_poll_unix"], 2000)
            self.assertFalse(result["success"])
            self.assertEqual(result["reason"], "key_receiver_requires_attention")
            with collector_lock(root / "key-receiver.lock"):
                pass
