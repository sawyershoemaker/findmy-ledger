import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from location_ledger import store
from research.auth_diagnostics import AuthTrace
try:
    from research.live_collector import run, HistorySink, HistoryWriteError, retry_delay, health
    from research.key_probe import RelationshipRevokedError
except ImportError:
    run = None


@unittest.skipIf(run is None, "Optional protocol dependencies")
class LiveCollectorTests(unittest.TestCase):
    def test_network_backoff_is_bounded_and_auth_or_binding_stops(self):
        trace = AuthTrace()
        self.assertEqual([retry_delay(ConnectionError(), trace, n) for n in (1, 2, 20)], [5, 10, 300])
        for error in (ValueError(), PermissionError(), HistoryWriteError(), RelationshipRevokedError()):
            self.assertIsNone(retry_delay(error, trace, 1))
        trace.http_status = 401
        self.assertIsNone(retry_delay(OSError(), trace, 1))
        trace.http_status = 429
        self.assertEqual(retry_delay(Exception(), trace, 1), 5)  # outer persisted cooldown takes precedence

    def test_transport_or_old_report_cannot_claim_current_location(self):
        self.assertFalse(health({}, {"invitation_accepted": True}, 1000)["live_collection_ready"])
        state = {"source_observed_unix": 900, "last_received_unix": 1000}
        self.assertFalse(health(state, {"native_live_ready": True}, 1000)["live_collection_ready"])
        quiet = health(state, {"native_live_ready": True, "invitation_accepted": True}, 1000)
        self.assertTrue(quiet["native_stream_connected"])
        self.assertEqual(quiet["state"], "waiting_for_location")
        state["source_observed_unix"] = 999
        self.assertTrue(health(state, {"native_live_ready": True}, 1000)["live_collection_ready"])
        self.assertFalse(health(state, {"native_live_ready": True}, 1100)["live_collection_ready"])

    def test_backfill_preserves_latest_status_and_is_stored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, database = Path(tmp), Path(tmp)/"history.sqlite"
            store.initialize(database)
            with store.connect(database, write=True) as db:
                store.register(db, "fixture")
            state = {}
            with patch("research.live_collector.selection_ready", return_value=True):
                sink = HistorySink(root, database, {"alias": "fixture"}, state)
                for stamp, received in ((1793232000, 1793232001), (1793231900, 1793232002)):
                    sink.record({"observed_at": stamp, "latitude": 40, "longitude": -75,
                        "accuracy_m": 10, "source": "findmy-people"}, received)
            self.assertEqual(state["source_observed_unix"], 1793232000)
            self.assertEqual(state["last_received_unix"], 1793232001)
            with store.connect(database) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM samples").fetchone()[0], 2)

    def test_conflicting_source_second_rejected_without_stopping_future_fixes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, database = Path(tmp), Path(tmp)/"history.sqlite"
            store.initialize(database)
            with store.connect(database, write=True) as db:
                store.register(db, "fixture")
            state = {}
            stamp = 1793232000
            with patch("research.live_collector.selection_ready", return_value=True):
                sink = HistorySink(root, database, {"alias": "fixture"}, state)
                for timestamp, lat in ((stamp, 40), (stamp, 41), (stamp+1, 40)):
                    sink.record({"observed_at": timestamp, "latitude": lat, "longitude": -75,
                        "accuracy_m": 10, "source": "findmy-people"}, stamp+5)
                sink.close()
            self.assertEqual(state["timestamp_collision_reports"], 1)
            self.assertEqual(state["reports_processed"], 2)
            self.assertEqual(state["source_observed_unix"], stamp+1)
            with store.connect(database) as db:
                from location_ledger.history import Run
                retained = [Run.from_row(row) for row in db.execute("SELECT * FROM samples")]
            self.assertEqual(sum(r.times.count for r in retained), 2)
            self.assertTrue(all(r.lat_e6 == 40000000 for r in retained))

    def test_real_write_failure_still_stops_with_redacted_reason(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as tmp:
            root, database = Path(tmp), Path(tmp)/"history.sqlite"
            store.initialize(database)
            with store.connect(database, write=True) as db:
                store.register(db, "fixture")
            with patch("research.live_collector.selection_ready", return_value=True):
                sink = HistorySink(root, database, {"alias": "fixture"}, {})
                with patch.object(sink.recorder, "accept", side_effect=sqlite3.OperationalError("private detail")):
                    with self.assertRaises(HistoryWriteError) as caught:
                        sink.record({}, 1793232000)
            self.assertEqual(caught.exception.reason, "sqlite_write_error")
            self.assertNotIn("private", str(caught.exception))

    def test_temporary_busy_write_retries_same_fix_once_without_duplicates(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as tmp:
            root, database = Path(tmp), Path(tmp)/"history.sqlite"
            store.initialize(database)
            with store.connect(database, write=True) as db:
                store.register(db, "fixture")
            state = {}
            with patch("research.live_collector.selection_ready", return_value=True), patch("research.live_collector.time.sleep"):
                sink = HistorySink(root, database, {"alias": "fixture"}, state)
                original = sink.recorder.accept
                busy = sqlite3.OperationalError("private SQL text")
                busy.sqlite_errorcode = sqlite3.SQLITE_BUSY
                calls = 0
                def once(*args, **kwargs):
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        raise busy
                    return original(*args, **kwargs)
                with patch.object(sink.recorder, "accept", side_effect=once):
                    sink.record({"observed_at": 1793232000, "latitude": 40, "longitude": -75,
                        "accuracy_m": 10, "source": "findmy-people"}, 1793232001)
                sink.close()
            self.assertEqual(state["storage_retry_attempts"], 1)
            self.assertEqual(state["storage_recoveries"], 1)
            self.assertEqual(state["reports_processed"], 1)
            with store.connect(database) as db:
                self.assertEqual(store.statistics(db)["samples"], 1)

    def test_persistent_storage_failure_is_recoverable_and_saved_redacted(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as tmp:
            root, database = Path(tmp), Path(tmp)/"history.sqlite"
            store.initialize(database)
            with store.connect(database, write=True) as db:
                store.register(db, "fixture")
            error = sqlite3.OperationalError("private data")
            error.sqlite_errorcode = sqlite3.SQLITE_FULL
            with patch("research.live_collector.selection_ready", return_value=True), patch("research.live_collector.time.sleep"):
                sink = HistorySink(root, database, {"alias": "fixture"}, {})
                with patch.object(sink.recorder, "accept", side_effect=error) as accept:
                    with self.assertRaises(HistoryWriteError) as caught:
                        sink.record({}, 1793232000)
                self.assertEqual(accept.call_count, 3)
                self.assertTrue(caught.exception.recoverable)
            saved = json.loads((root/"collector-last-failure.json").read_text())
            self.assertEqual(saved["sqlite_errorcode"], sqlite3.SQLITE_FULL)
            self.assertTrue(saved["automatic_recovery"])
            self.assertNotIn("private", json.dumps(saved))

    def test_flush_error_cannot_make_auth_or_pause_failure_restartable(self):
        from research.live_collector import mark_flush_failure
        error = HistoryWriteError("sqlite_write_error", details={"automatic_recovery": True})
        for state in ("paused", "stopped", "needs_attention"):
            status = {"state": state, "reason": "requires_user", "automatic_recovery": False}
            mark_flush_failure(status, error)
            self.assertEqual(status["state"], state)
            self.assertFalse(status["automatic_recovery"])

    def test_run_exits_with_recoverable_status_when_write_and_cleanup_both_fail(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as tmp:
            root, database = Path(tmp), Path(tmp)/"history.sqlite"
            store.initialize(database)
            with store.connect(database, write=True) as db:
                store.register(db, "fixture")
            selected = {"alias": "fixture"}
            full = sqlite3.OperationalError("private detail")
            full.sqlite_errorcode = sqlite3.SQLITE_FULL
            async def failing_probe(directory, database, details, **options):
                details.update(invitation_sent=True, native_live_ready=True)
                options["on_observation"]({"observed_at": 1793232000, "latitude": 40,
                    "longitude": -75, "accuracy_m": 10, "source": "findmy-people"}, 1793232001)
            with patch("research.live_collector.prerequisite", return_value={"ready": True}), \
                    patch("research.live_collector.load", return_value=selected), \
                    patch("research.live_collector.selection_ready", return_value=True), \
                    patch("research.live_collector.probe", side_effect=failing_probe), \
                    patch("research.live_collector.time.sleep"), \
                    patch("location_ledger.stay_recorder.StayRecorder.accept", side_effect=full), \
                    patch("location_ledger.stay_recorder.StayRecorder.flush", side_effect=full):
                status = asyncio.run(run(root, database))
            self.assertEqual(status["reason"], "history_write_failed")
            self.assertTrue(status["automatic_recovery"])
            self.assertEqual(status["history_failure_reason"], "sqlite_write_error")
            self.assertNotIn("private", json.dumps(status))

    def exercise(self, stop):
        with tempfile.TemporaryDirectory() as tmp:
            root, dbpath = Path(tmp), Path(tmp)/"history.sqlite"
            store.initialize(dbpath)
            with store.connect(dbpath, write=True) as db:
                store.register(db, "fixture")
            selection = {"alias": "fixture"}
            now = 1793232000
            async def fake_probe(directory, database, details, **options):
                for stamp in (now, now+5, now+10):
                    options["on_observation"]({"observed_at": stamp, "latitude": 40, "longitude": -75,
                        "accuracy_m": 10, "source": "findmy-people"}, stamp)
                details.update(native_live_ready=True, authenticated_reports=3, invitation_sent=True)
                if stop == "quiet":
                    details.update(phase="live_location_refresh", quiet_session_renewal=True)
                if stop == "revoked":
                    raise RelationshipRevokedError()
                if stop == "paused":
                    with store.connect(database, write=True) as db:
                        db.execute("UPDATE subjects SET active=0")
                    options["on_tick"](details)
                (directory/"live-stop.request").touch()

            def allowed(directory, database, expected):
                with store.connect(database) as db:
                    return bool(store.subject(db, "fixture")["active"])

            with patch("research.live_collector.prerequisite", return_value={"ready": True}), \
                    patch("research.live_collector.load", return_value=selection), \
                    patch("research.live_collector.selection_ready", side_effect=allowed), \
                    patch("research.live_collector.probe", side_effect=fake_probe):
                status = asyncio.run(run(root, dbpath))
            with store.connect(dbpath) as db:
                from location_ledger.history import Run
                rows = [(r['observed_at'], Run.from_row(r).times.last, Run.from_row(r).times.count)
                        for r in db.execute('SELECT * FROM samples ORDER BY observed_at')]
                active = bool(store.subject(db, "fixture")["active"])
            saved = json.loads((root/"collector-status.json").read_text())
            self.assertNotIn("latitude", json.dumps(saved))
            self.assertEqual(saved["reports_coalesced"], 2)
            return status, rows, active

    def test_orderly_stop_commits_pending_endpoint(self):
        status, rows, active = self.exercise("normal")
        self.assertEqual(rows, [(1793232000, 1793232010, 3)])
        self.assertTrue(active)
        self.assertEqual(status["state"], "stopped")

    def test_quiet_stream_renewal_preserves_restart_delay_without_fabricating_fixes(self):
        status, rows, active = self.exercise("quiet")
        self.assertEqual(rows, [(1793232000, 1793232010, 3)])
        self.assertTrue(active)
        self.assertEqual(status["quiet_session_renewals"], 1)
        self.assertGreaterEqual(status["next_connect_unix"] - status["heartbeat_unix"], 29)
        self.assertFalse(status["native_stream_connected"])

    def test_revoked_share_discards_pending_endpoint_and_pauses_history(self):
        status, rows, active = self.exercise("revoked")
        self.assertEqual(rows, [(1793232000, 1793232000, 1)])
        self.assertFalse(active)
        self.assertEqual(status["reason"], "sharing_relationship_unavailable")

    def test_local_pause_stops_and_discards_pending_endpoint(self):
        status, rows, active = self.exercise("paused")
        self.assertEqual(rows, [(1793232000, 1793232000, 1)])
        self.assertFalse(active)
        self.assertEqual(status["state"], "paused")
