"""Foreground Windows collector, gated on a previously verified real Find My fix."""
import argparse
import asyncio
from contextlib import contextmanager
import json
import logging
import os
from pathlib import Path
import sqlite3
import time
from uuid import uuid4

from location_ledger import maintenance, store
from . import auth_cooldown, searchparty_backoff
from .auth_diagnostics import AuthTrace
from .windows_secrets import load


def write_status(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + "." + uuid4().hex + ".tmp")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def collector_lock(path):
    """The OS releases this lock even if the process crashes; stale files are harmless."""
    with Path(path).open("a+b") as stream:
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                raise RuntimeError("Another collector holds this state directory") from None
        else:
            import fcntl
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)


def prerequisite(directory, database):
    required = ["apple-session.dpapi", "mac-machine.dpapi", "selected-person.dpapi", "apns.dpapi", "ids.dpapi",
                "people-key.dpapi", "latest-fix.dpapi"]
    missing = [name for name in required if not (directory / name).is_file()]
    if missing:
        return {"ready": False, "reason": "verified_live_bootstrap_required", "missing_files": missing}
    from .saved_session import restore
    from .key_probe import validate_saved_key
    state, provider = restore(directory)
    # Restoring only reads local state and does not create a network session.
    selection = load(directory / "selected-person.dpapi")
    key = load(directory / "people-key.dpapi")
    preview = load(directory / "latest-fix.dpapi")
    dsid, device = state["login"]["data"]["dsid"], provider.account_ids["devid"]
    validate_saved_key(key, selection, dsid=dsid, device_id=device)
    if (preview.get("account_dsid") != dsid or preview.get("fm_id") != selection["relationship"]["fm_id"]
            or preview.get("observation", {}).get("source") != "findmy-people"):
        raise ValueError("Previously verified live fix does not match this participant")
    alias = store.text_label(selection["alias"], "Participant alias")
    if database.exists():
        with store.connect(database) as db:
            if not store.subject(db, alias)["active"]:
                return {"ready": False, "reason": "participant_paused"}
    return {"ready": True, "reason": "verified_bootstrap_available"}


def schedule(result, failures, interval, *, now, retry_503_locally=False):
    if result.get("stop_reason"):
        return {"state": "needs_attention", "reason": result["stop_reason"], "failures": failures,
                "next_poll_unix": None}
    fresh = result.get("success") is True and result.get("fresh_report_received") is True
    delayed = result.get("success") is True and result.get("delayed_report_received") is True and result.get("new_observation") is True
    progress = fresh or delayed
    failures = 0 if progress else min(failures + 1, 16)
    delay = interval if progress else min(3600, interval * 2 ** min(failures - 1, 6))
    remaining = result.get("seconds_remaining")
    if type(remaining) is int and remaining > 0:
        delay = max(delay, remaining)
    details = result.get("searchparty_response", result)
    retry_after = details.get("retry_after_seconds")
    if details.get("http_status") == 429 or (details.get("http_status") == 503 and not retry_503_locally):
        delay = max(delay, retry_after if type(retry_after) is int and retry_after >= 0 else 2700)
    return {"state": "collecting" if progress else "waiting",
            "reason": "fresh_location" if fresh else "delayed_location_recorded" if delayed else "no_fresh_location",
            "failures": failures, "next_poll_unix": int(now + delay)}


async def poll(directory, database, *, retry_503_locally=False):
    from .key_probe import RelationshipRevokedError
    from .location_probe import LocationReportError, probe
    result = {"success": False, "fresh_report_received": False}
    trace = AuthTrace()
    try:
        await asyncio.wait_for(probe(directory, trace, result, database=database, accept_delayed=True,
                                    ignore_503_backoff=retry_503_locally), timeout=120)
    except RelationshipRevokedError:
        selection = load(directory / "selected-person.dpapi")
        if database.exists():
            with store.connect(database, write=True) as db:
                sid = store.subject(db, selection["alias"])["id"]
                db.execute("UPDATE subjects SET active=0 WHERE id=?", (sid,))
        result["stop_reason"] = "sharing_relationship_unavailable"
    except Exception as error:
        result.update(trace.failure(error))
        if trace.http_status in (401, 403):
            result["stop_reason"] = "local_sign_in_required"
        elif isinstance(error, (ValueError, KeyError, TypeError, LocationReportError)):
            result["stop_reason"] = "binding_or_report_validation_failed"
        elif not isinstance(error, (OSError, TimeoutError)) and trace.http_status not in (429, 500, 502, 503, 504):
            # Unknown protocol failures require inspection, not an endless request loop.
            result["stop_reason"] = "protocol_failure_requires_attention"
    return result


async def run(directory, database, *, interval=300, max_polls=None, retention_days=None, backup_dir=None, backup_keep=7,
              receiver_ready=None, retry_503_locally=False):
    status_path = directory / "collector-status.json"
    result = {"stage": "collector", "success": False, "live_collection_ready": False}
    gate = prerequisite(directory, database)
    if not gate["ready"]:
        paused = gate["reason"] == "participant_paused"
        result.update(gate, state="paused" if paused else "needs_attention", success=paused)
        write_status(status_path, result)
        return result
    selection = load(directory / "selected-person.dpapi")
    previous = json.loads(status_path.read_text(encoding="utf-8")) if status_path.exists() else {}
    due, failures = previous.get("next_poll_unix"), previous.get("failures", 0)
    if type(failures) is not int or not 0 <= failures <= 16 or (due is not None and (type(due) is not int or due < 0)):
        raise ValueError("Invalid saved collector schedule")
    count = 0
    last_backup = previous.get("last_backup_unix", 0)
    if type(last_backup) is not int or last_backup < 0:
        raise ValueError("Invalid saved backup schedule")
    while max_polls is None or count < max_polls:
        if load(directory / "selected-person.dpapi") != selection:
            result.update(state="needs_attention", reason="participant_selection_changed", next_poll_unix=None,
                          success=False, live_collection_ready=False)
            break
        gate = prerequisite(directory, database)
        if not gate["ready"]:
            paused = gate["reason"] == "participant_paused"
            result.update(gate, state="paused" if paused else "needs_attention", next_poll_unix=None,
                          success=paused, live_collection_ready=False)
            break
        if receiver_ready is not None and not receiver_ready.is_set():
            await asyncio.sleep(1)
            continue
        now = time.time()
        for pending in (auth_cooldown.active(directory, now=now),
                        searchparty_backoff.active(directory, now=now, ignore_503=retry_503_locally)):
            if pending:
                due = max(due or 0, int(now + pending["seconds_remaining"]))
        if due is not None and due > now:
            await asyncio.sleep(min(10, due - now))
            continue
        current = await poll(directory, database, retry_503_locally=True) if retry_503_locally else await poll(directory, database)
        count += 1
        now = time.time()
        next_state = schedule(current, failures, interval, now=now, retry_503_locally=retry_503_locally)
        failures, due = next_state["failures"], next_state["next_poll_unix"]
        result = {"stage": "collector", "success": current.get("success") is True,
                  "live_collection_ready": current.get("fresh_report_received") is True,
                  "last_poll_utc": auth_cooldown.utc_text(now), "new_observation": current.get("new_observation", False),
                  "last_backup_unix": last_backup, **next_state}
        result["retry_503_policy"] = "local_exponential" if retry_503_locally else "server_retry_after"
        for field in ("source_observed_at_utc", "source_age_seconds", "accuracy_m", "searchparty_response"):
            if field in current:
                result[field] = current[field]
        if current.get("error_type"):
            result["last_error_type"] = current["error_type"]
            result["last_error_reason"] = current.get("reason", "unknown")
        # Commit the deadline before maintenance: a backup error or interruption
        # must not cause a rapid extra poll on restart.
        write_status(status_path, result)
        if current.get("success") and database.exists():
            try:
                if retention_days is not None:
                    with store.connect(database, write=True) as db:
                        maintenance.retain(db, selection["alias"], int(now - retention_days * 86400), apply=True)
                if backup_dir is not None and now - last_backup >= 86400:
                    target = backup_dir / ("ledger-" + str(int(now)) + "-" + uuid4().hex[:8] + ".sqlite")
                    maintenance.backup(database, target)
                    last_backup = int(now)
                    result["last_backup_unix"] = last_backup
                    result.update(maintenance.rotate_backups(backup_dir, keep=backup_keep))
            except (OSError, sqlite3.Error, ValueError):
                result["maintenance_warning"] = "retention_or_backup_failed"
        write_status(status_path, result)
        print(json.dumps(result), flush=True)
        if due is None:
            break
    write_status(status_path, result)
    return result


async def run_until_stopped(directory, database, **options):
    """Record an orderly cancellation while still holding the writer lock."""
    try:
        return await run(directory, database, **options)
    except asyncio.CancelledError:
        status_path = directory / "collector-status.json"
        result = json.loads(status_path.read_text(encoding="utf-8")) if status_path.exists() else {}
        result.update(stage="collector", state="stopped", reason="local_stop")
        write_status(status_path, result)
        raise


async def serve(directory, database, **options):
    """Keep the authenticated key receiver alive alongside location polling."""
    if not prerequisite(directory, database)["ready"]:
        return await run_until_stopped(directory, database, **options)
    from .key_listener import run as receive_keys
    with collector_lock(directory / "key-receiver.lock"):
        ready = asyncio.Event()
        polling = asyncio.create_task(run_until_stopped(directory, database, receiver_ready=ready, **options))
        receiver = None
        try:
            while True:
                receiver = asyncio.create_task(receive_keys(directory, database, duration=86400, ready_event=ready))
                done, _ = await asyncio.wait({polling, receiver}, return_when=asyncio.FIRST_COMPLETED)
                if polling in done:
                    return polling.result()
                status = receiver.result()
                if status.get("reason") != "bounded_listening_window_finished":
                    polling.cancel()
                    await asyncio.gather(polling, return_exceptions=True)
                    path = directory / "collector-status.json"
                    result = json.loads(path.read_text()) if path.exists() else {}
                    paused = prerequisite(directory, database).get("reason") == "participant_paused"
                    result.update(state="paused" if paused else "needs_attention",
                                  reason="participant_paused" if paused else "key_receiver_requires_attention", success=paused,
                                  live_collection_ready=False)
                    write_status(path, result)
                    return result
                # Re-open a bounded listener after each day; no key-distribution
                # request is made while a verified sharing key is already saved.
        finally:
            for task in (polling, receiver):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(*(task for task in (polling, receiver) if task is not None), return_exceptions=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("doctor", "once", "run"))
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--interval", type=int, default=300)
    parser.add_argument("--retention-days", type=int)
    parser.add_argument("--backup-dir", type=Path)
    parser.add_argument("--backup-keep", type=int, default=7)
    parser.add_argument("--retry-503-locally", action="store_true",
                        help="Use the local exponential schedule for 503 responses; 429 deadlines remain enforced")
    args = parser.parse_args()
    if not 60 <= args.interval <= 3600 or (args.retention_days is not None and not 1 <= args.retention_days <= 36500):
        parser.error("Interval must be 60-3600 seconds; retention must be 1-36500 days")
    if not 1 <= args.backup_keep <= 365:
        parser.error("Keep must be 1-365 backups")
    logging.disable(logging.CRITICAL)
    directory, database = args.state_dir.resolve(), args.db.resolve()
    result = {}
    try:
        directory.mkdir(parents=True, exist_ok=True)
        if args.command == "doctor":
            result = {"stage": "collector_preflight", **prerequisite(directory, database), "network_requests": 0}
        else:
            with collector_lock(directory / "collector.lock"):
                runner = serve if args.command == "run" else run_until_stopped
                result = asyncio.run(runner(directory, database, interval=args.interval,
                    max_polls=1 if args.command == "once" else None, retention_days=args.retention_days,
                    backup_dir=args.backup_dir.resolve() if args.backup_dir else None, backup_keep=args.backup_keep,
                    retry_503_locally=args.retry_503_locally))
    except KeyboardInterrupt:
        result = {"stage": "collector", "success": False, "state": "stopped", "reason": "local_stop"}
        # The async cancellation handler retained the deadline before releasing
        # the lock. Do not overwrite it here after another collector may start.
    except Exception:
        result = {"stage": "collector", "success": False, "state": "needs_attention", "reason": "local_state_or_runtime_error"}
        # Preserve the last completed poll/schedule when startup cannot acquire its lock.
    print(json.dumps(result, indent=2))
    return 0 if result.get("success", result.get("ready", False)) else 2


if __name__ == "__main__":
    raise SystemExit(main())
