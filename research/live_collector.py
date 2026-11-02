"""Continuous selected-person Live sessions with adaptive SQLite history."""
import argparse
import asyncio
import json
import logging
import os
from pathlib import Path
import random
import sqlite3
import time
from uuid import uuid4

from location_ledger import maintenance, store
from location_ledger.history import ConflictingObservationError, StayPolicy
from location_ledger.stay_recorder import StayRecorder
from . import auth_cooldown
from .auth_diagnostics import AuthTrace
from .collector import collector_lock, prerequisite, write_status
from .key_listener import selection_ready
from .key_probe import RelationshipRevokedError
from .live_probe import probe
from .windows_secrets import load
from .recovery import storage_failure, save_failure


class HistoryWriteError(Exception):
    def __init__(self, reason="history_commit_failed", *, details=None):
        super().__init__(reason)
        self.reason = reason
        self.details = details or {"reason": reason, "automatic_recovery": False}
        self.recoverable = self.details["automatic_recovery"]


def history_failure_reason(error):
    return storage_failure(error)["reason"]


def mark_flush_failure(status, error):
    status["flush_failure_reason"] = error.reason
    # Cleanup must not convert an auth/pause/manual-stop decision into an
    # automatically retryable storage exit.
    if status.get("state") in ("paused", "stopped") or (
            status.get("state") == "needs_attention" and status.get("automatic_recovery") is not True):
        return
    status.update(state="needs_attention", reason="history_write_failed", live_collection_ready=False,
                  history_failure_reason=error.reason, automatic_recovery=error.recoverable)


def retry_delay(error, trace, failures):
    """None means manual attention; transient network errors reconnect boundedly."""
    if isinstance(error, (PermissionError, RelationshipRevokedError, HistoryWriteError)):
        return None
    if trace.http_status in (401, 403) or isinstance(error, (ValueError, KeyError, TypeError)):
        return None
    transient = (isinstance(error, (OSError, TimeoutError)) or
        type(error).__name__ in {"EndOfStream", "BrokenResourceError", "ClosedResourceError",
            "ClientConnectionError", "ClientConnectorError", "ClientOSError", "ServerDisconnectedError"}
        or trace.http_status in (429, 500, 502, 503, 504))
    return min(300, 5 * 2 ** min(max(failures-1, 0), 6)) if transient else None


class HistorySink:
    def __init__(self, directory, database, selection, status, policy=None):
        self.directory, self.database, self.selection, self.status = directory, database, selection, status
        self.recorder = StayRecorder(database, selection["alias"], policy)
        status["sampling"] = self.recorder.configuration()

    def allowed(self):
        return selection_ready(self.directory, self.database, self.selection)

    def storage_call(self, operation, phase):
        for attempt in range(3):
            if not self.allowed():
                raise PermissionError("Participant selection changed or paused")
            try:
                result = operation()
            except ConflictingObservationError:
                raise
            except (OSError, sqlite3.Error, ValueError) as error:
                details = storage_failure(error)
                self.status["last_storage_error"] = {**details, "phase": phase}
                if details["automatic_recovery"] and attempt < 2:
                    self.status["storage_retry_attempts"] = self.status.get("storage_retry_attempts", 0) + 1
                    time.sleep((0.25, 1)[attempt])
                    continue
                try:
                    save_failure(self.directory, details, phase=phase)
                except OSError:
                    pass  # A full/unavailable disk may also prevent diagnostics.
                raise HistoryWriteError(details["reason"], details=details) from error
            if attempt:
                self.status["storage_recoveries"] = self.status.get("storage_recoveries", 0) + 1
            return result

    def record(self, observation, received_at):
        if not self.allowed():
            raise PermissionError("Participant selection changed or paused")
        try:
            decision = self.storage_call(lambda: self.recorder.accept(observation, received_at=received_at), "record")
        except ConflictingObservationError:
            # The schema resolves source times to whole seconds. An authenticated
            # revised/subsecond fix must not replace already represented evidence
            # or stop future seconds from being recorded. Imports remain strict.
            self.status["timestamp_collision_reports"] = self.status.get("timestamp_collision_reports", 0) + 1
            self.status["last_rejected_report_reason"] = "source_second_already_has_different_value"
            return
        self.status["reports_processed"] = self.status.get("reports_processed", 0) + 1
        self.status["samples_inserted"] = self.status.get("samples_inserted", 0) + decision["inserted"]
        self.status["reports_coalesced"] = self.status.get("reports_coalesced", 0) + int(decision["coalesced"])
        self.status["duplicate_reports"] = self.status.get("duplicate_reports", 0) + decision["duplicates"]
        self.status["stay_checkpoints"] = self.status.get("stay_checkpoints", 0) + decision.get("updated", 0)
        reasons = self.status.setdefault("sampling_reasons", {})
        reasons[decision["reason"]] = reasons.get(decision["reason"], 0) + 1
        # Backfill is valid history but must not replace the current fix in
        # health/status. Native sessions can deliver cached reports out of order.
        if observation["observed_at"] >= self.status.get("source_observed_unix", 0):
            self.status.update(last_received_unix=received_at, source_observed_at_utc=store.iso(observation["observed_at"]),
                source_observed_unix=observation["observed_at"], accuracy_m=observation["accuracy_m"])

    def close(self, *, discard=False):
        if discard or not self.allowed():
            self.recorder.discard()
            return
        decision = self.storage_call(self.recorder.flush, "flush")
        self.status["samples_inserted"] = self.status.get("samples_inserted", 0) + decision["inserted"]
        self.status['stay_checkpoints'] = self.status.get('stay_checkpoints', 0) + decision.get('updated', 0)

    def checkpoint(self):
        if not self.allowed():
            raise PermissionError('Participant selection changed or paused')
        result = self.storage_call(self.recorder.checkpoint, "checkpoint")
        self.status['stay_checkpoints'] = self.status.get('stay_checkpoints', 0) + result.get('updated', 0)


def health(status, details, now):
    age = now - status["source_observed_unix"] if "source_observed_unix" in status else None
    received_age = now - status["last_received_unix"] if "last_received_unix" in status else None
    fresh = bool(details.get("native_live_ready") and age is not None and -300 <= age <= 90
                 and received_age is not None and received_age <= 90)
    return {"state": "collecting" if fresh else "waiting_for_location" if details.get("invitation_accepted") else "connecting",
        "reason": "native_live_updates" if fresh else "source_not_current" if details.get("invitation_accepted") else "opening_native_live",
        "live_collection_ready": fresh, "source_age_seconds": age,
        "native_stream_connected": bool(details.get("invitation_accepted") and details.get("native_live_ready")),
        "heartbeat_utc": store.iso(now), "heartbeat_unix": now}


async def run(directory, database, *, duration=None, policy=None, backup_dir=None, backup_keep=7, retention_days=None):
    path = directory / "collector-status.json"
    gate = prerequisite(directory, database)
    if not gate["ready"]:
        result = {"stage": "live_collector", "mode": "continuous_live", "state": "paused" if gate["reason"] == "participant_paused" else "needs_attention", **gate}
        write_status(path, result)
        return result
    selection = load(directory / "selected-person.dpapi")
    previous = json.loads(path.read_text()) if path.exists() else {}
    status = {"stage": "live_collector", "mode": "continuous_live", "state": "starting", "success": False,
        "live_collection_ready": False, "automatic_login": False, "process_id": os.getpid(),
        "started_utc": store.iso(int(time.time())), "sessions_started": 0}
    for field in ("reports_processed", "samples_inserted", "reports_coalesced", "duplicate_reports", "last_backup_unix", "quiet_session_renewals", "stay_checkpoints", "timestamp_collision_reports", "storage_retry_attempts", "storage_recoveries"):
        value = previous.get(field, 0)
        status[field] = value if type(value) is int and value >= 0 else 0
    sink = HistorySink(directory, database, selection, status, policy)
    started, last_write, last_maintenance = time.monotonic(), 0, 0
    deadline = started + duration if duration is not None else float("inf")
    due = previous.get("next_connect_unix", 0) if previous.get("mode") == "continuous_live" else 0
    if type(due) not in (int, float) or not 0 <= due <= time.time() + 86400 * 30:
        due = 0
    failures = 0
    discard = False
    details = {}

    def tick(current):
        nonlocal last_write, last_maintenance
        if not sink.allowed():
            raise PermissionError("Participant changed or paused")
        if ((directory / "live-stop.request").exists() or (directory / "live-restart.request").exists()
                or time.monotonic() >= deadline):
            raise asyncio.CancelledError()
        now = int(time.time())
        status.update(health(status, current, now))
        status["session"] = {k: current[k] for k in ("phase", "invitation_accepted", "native_live_ready",
            "authenticated_reports", "heartbeats_sent", "heartbeat_requests", "heartbeat_replies",
            "rejected_packets", "key_rotations", "relationship_checked_unix") if k in current}
        if time.monotonic() - last_maintenance >= 60:
            last_maintenance = time.monotonic()
            try:
                if retention_days is not None:
                    sink.close()
                    with store.connect(database, write=True) as db:
                        maintenance.retain(db, selection["alias"], now - retention_days*86400, apply=True)
                    sink.recorder.reload()
                if backup_dir is not None and now - status["last_backup_unix"] >= 86400:
                    target = backup_dir / ("ledger-"+str(now)+"-"+uuid4().hex[:8]+".sqlite")
                    maintenance.backup(database, target)
                    status["last_backup_unix"] = now
                    status.update(maintenance.rotate_backups(backup_dir, keep=backup_keep))
                status.pop("maintenance_warning", None)
            except (OSError, sqlite3.Error, ValueError):
                status["maintenance_warning"] = "retention_or_backup_failed"
        if time.monotonic() - last_write >= 10:
            sink.checkpoint()
            last_write = time.monotonic()
            if status["live_collection_ready"]:
                status["success"] = True
                status.pop("error_type", None)
                status.pop("http_status", None)
            write_status(path, status)
            write_status(directory / "live-session-status.json", current)

    try:
        while time.monotonic() < deadline:
            if not sink.allowed():
                raise PermissionError("Participant changed or paused")
            if (directory / "live-stop.request").exists() or (directory / "live-restart.request").exists():
                status.update(state="stopped", reason="local_stop" if (directory / "live-stop.request").exists() else "watchdog_restart")
                break
            pause = auth_cooldown.active(directory)
            if pause:
                due = max(due, time.time() + pause["seconds_remaining"])
            if time.time() < due:
                status.update(state="waiting", reason="account_cooldown" if pause else "reconnecting",
                    next_connect_unix=int(due), live_collection_ready=False, heartbeat_utc=store.iso(int(time.time())), heartbeat_unix=int(time.time()))
                write_status(path, status)
                await asyncio.sleep(min(5, due-time.time(), max(0, deadline-time.monotonic())))
                continue
            details = {"native_live_ready": False}
            trace = AuthTrace()
            status.update(state="connecting", reason="opening_native_live", next_connect_unix=0,
                          live_collection_ready=False, sessions_started=status["sessions_started"]+1)
            write_status(path, status)
            try:
                # Renew the relationship, directory, and cryptographic session each
                # half hour; packet counters never continue across fresh sessions.
                session_seconds = min(1800, deadline-time.monotonic())
                async with asyncio.timeout(session_seconds + 120):
                    await probe(directory, database, details, mode="transport", duration=session_seconds,
                        capture=False, on_observation=sink.record, on_tick=tick, trace=trace,
                        quiet_after=max(60, min(1800, sink.recorder.policy.stationary_seconds)))
                if not details.get("native_live_ready"):
                    raise ConnectionError("Native Live session unavailable")
                failures = 0
                due = time.time() + 30
                status.update(state="waiting", reason="renewing_quiet_live_session" if details.get("quiet_session_renewal")
                    else "renewing_native_live_session", live_collection_ready=False, native_stream_connected=False,
                    next_connect_unix=int(due))
                if details.get("quiet_session_renewal"):
                    status["quiet_session_renewals"] = status.get("quiet_session_renewals", 0) + 1
            except asyncio.CancelledError:
                raise
            except Exception as error:
                if isinstance(error, sqlite3.Error):
                    # Read/selection gates can encounter a database lock too;
                    # preserve the same recovery policy as a write callback.
                    details_for_error = storage_failure(error)
                    error = HistoryWriteError(details_for_error["reason"], details=details_for_error)
                    save_failure(directory, details_for_error, phase="database_gate")
                if isinstance(error, (PermissionError, RelationshipRevokedError)):
                    discard = True
                    raise
                failure = trace.failure(error)
                auth_cooldown.record(directory, failure)
                # A sustained stream resets the failure budget before reconnect.
                failures = 1 if details.get("authenticated_reports", 0) >= 10 else failures+1
                delay = retry_delay(error, trace, failures)
                status.update(live_collection_ready=False, error_type=type(error).__name__,
                    http_status=trace.http_status, failures=failures)
                if delay is None:
                    status.update(state="needs_attention", reason="history_write_failed" if isinstance(error, HistoryWriteError)
                        else "authentication_or_protocol_requires_attention")
                    if isinstance(error, HistoryWriteError):
                        status["history_failure_reason"] = error.reason
                        status["automatic_recovery"] = error.recoverable
                    else:
                        status["automatic_recovery"] = False
                        save_failure(directory, {"reason": status["reason"], "automatic_recovery": False,
                            "error_type": type(error).__name__}, phase=details.get("phase", "session"))
                    break
                due = time.time() + delay + random.uniform(0, min(5, delay/5))
                status.update(state="waiting", reason="reconnecting", next_connect_unix=int(due))
            finally:
                if details.get("invitation_sent"):
                    # Let remote teardown finish before a replacement, including
                    # across a process restart. All source monitoring is scoped
                    # to the account on the publishing phone.
                    due = max(due, time.time() + 30)
                    status["next_connect_unix"] = int(due)
                status["native_stream_connected"] = False
                try:
                    sink.close(discard=discard)
                except HistoryWriteError as error:
                    mark_flush_failure(status, error)
                except PermissionError:
                    discard = True
                    raise
                status["last_session"] = {k: details[k] for k in ("phase", "native_live_ready", "authenticated_reports",
                    "heartbeats_sent", "heartbeat_requests", "heartbeat_replies", "rejected_packets") if k in details}
                write_status(path, status)
                write_status(directory / "live-session-status.json", details)
            if status["state"] == "needs_attention":
                break
    except RelationshipRevokedError:
        discard = True
        with store.connect(database, write=True) as db:
            sid = store.subject(db, selection["alias"])["id"]
            db.execute("UPDATE subjects SET active=0 WHERE id=?", (sid,))
        status.update(state="paused", reason="sharing_relationship_unavailable", live_collection_ready=False)
    except PermissionError:
        discard = True
        status.update(state="paused", reason="selection_changed_or_paused", live_collection_ready=False)
    except asyncio.CancelledError:
        reason = ("local_stop" if (directory / "live-stop.request").exists() else
                  "watchdog_restart" if (directory / "live-restart.request").exists() else "bounded_run_finished")
        status.update(state="stopped", reason=reason, live_collection_ready=False)
    finally:
        try:
            sink.close(discard=discard)
        except HistoryWriteError as error:
            mark_flush_failure(status, error)
        except PermissionError:
            sink.close(discard=True)
            status.update(state="paused", reason="selection_changed_or_paused", live_collection_ready=False)
        if status["state"] not in ("paused", "needs_attention", "stopped"):
            status.update(state="stopped", reason="bounded_run_finished", live_collection_ready=False)
        status["success"] = status.get("reports_processed", 0) > previous.get("reports_processed", 0)
        status.update(heartbeat_utc=store.iso(int(time.time())), heartbeat_unix=int(time.time()))
        write_status(path, status)
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("doctor", "run"))
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--duration", type=int)
    parser.add_argument("--stationary-seconds", type=int, default=300)
    parser.add_argument("--movement-m", type=float, help="Legacy alias for --stay-radius-m")
    parser.add_argument("--stay-radius-m", type=float)
    parser.add_argument("--stay-gap-seconds", type=int, default=600)
    parser.add_argument("--checkpoint-seconds", type=int, default=30)
    parser.add_argument("--retention-days", type=int)
    parser.add_argument("--backup-dir", type=Path)
    parser.add_argument("--backup-keep", type=int, default=7)
    args = parser.parse_args()
    if (args.duration is not None and not 10 <= args.duration <= 86400 or
            args.retention_days is not None and not 1 <= args.retention_days <= 36500 or not 1 <= args.backup_keep <= 365):
        parser.error("Invalid duration, retention, or backup count")
    policy = StayPolicy(radius_m=args.stay_radius_m if args.stay_radius_m is not None else
                        args.movement_m if args.movement_m is not None else 25,
                        stationary_seconds=args.stationary_seconds, gap_seconds=args.stay_gap_seconds,
                        checkpoint_seconds=args.checkpoint_seconds)
    logging.disable(logging.CRITICAL)
    directory, database = args.state_dir.resolve(), args.db.resolve()
    result = {}
    try:
        if args.command == "doctor":
            result = {"stage": "live_preflight", **prerequisite(directory, database), "network_requests": 0}
            if result.get('ready'):
                with store.connect(database) as db:
                    if db.execute('PRAGMA user_version').fetchone()[0] != 2:
                        result.update(ready=False, reason='history_upgrade_required')
        else:
            with collector_lock(directory / "collector.lock"), collector_lock(directory / "key-receiver.lock"):
                try:
                    result = asyncio.run(run(directory, database, duration=args.duration, policy=policy,
                        backup_dir=args.backup_dir.resolve() if args.backup_dir else None, backup_keep=args.backup_keep,
                        retention_days=args.retention_days))
                except Exception as error:
                    details = storage_failure(error)
                    result = {"stage": "live_collector", "mode": "continuous_live", "state": "needs_attention",
                        "reason": "local_runtime_error", "error_type": type(error).__name__, "live_collection_ready": False,
                        "automatic_recovery": details["automatic_recovery"], "process_id": os.getpid(),
                        "heartbeat_unix": int(time.time())}
                    save_failure(directory, details, phase="runtime")
                    write_status(directory / "collector-status.json", result)
    except (Exception, KeyboardInterrupt) as error:
        result = {"stage": "live_collector", "state": "needs_attention", "error_type": type(error).__name__, "live_collection_ready": False}
    if sys_stdout_available():
        print(json.dumps(result, indent=2))
    # A manual attention condition exits cleanly: Task Scheduler must not turn it
    # into repeated authentication attempts. Transient errors retry in-process.
    if result.get("automatic_recovery"):
        return 2
    return 0 if result.get("state") in ("needs_attention", "paused", "stopped") or result.get("success", result.get("ready", False)) else 2


def sys_stdout_available():
    import sys
    return sys.stdout is not None


if __name__ == "__main__":
    raise SystemExit(main())
