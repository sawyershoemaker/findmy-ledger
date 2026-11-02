"""Receive only the selected participant's authenticated sharing-key updates.

An optional bounded bootstrap request is sent no more than once per 30 minutes
while no key exists. Account/service cooldowns persist. There is no auto-login.
"""
import argparse
import asyncio
import json
import logging
import os
from pathlib import Path
import time

from location_ledger import store
from . import auth_cooldown, searchparty_backoff
from .auth_diagnostics import AuthTrace
from .collector import collector_lock, write_status
from .windows_secrets import load


def selection_ready(directory, database, expected):
    current = load(directory / "selected-person.dpapi")
    # Old selections may contain the retired acknowledgement field. Ignore it
    # when comparing identities; pause/resume is controlled by the database.
    current_identity = {k: v for k, v in current.items() if k != "consent_to_history_and_analysis"}
    expected_identity = {k: v for k, v in expected.items() if k != "consent_to_history_and_analysis"}
    if current_identity != expected_identity:
        return False
    if database is not None and database.exists():
        with store.connect(database) as db:
            if not store.subject(db, current["alias"])["active"]:
                return False
    return True


def next_request_allowed(directory, now, saved_deadline):
    deadline = saved_deadline
    request_record = directory / "key-request-status.json"
    if request_record.exists():
        latest = json.loads(request_record.read_text()).get("next_bootstrap_request_unix")
        if type(latest) is not int or latest < 0:
            raise ValueError("Invalid saved distribution deadline")
        deadline = max(deadline, latest)
    for gate in (auth_cooldown.active(directory, now=now), searchparty_backoff.active(directory, now=now)):
        if gate:
            deadline = max(deadline, now + gate["seconds_remaining"])
    return deadline


async def run(directory, database=None, *, duration=3600, request_missing=False, stop_after_key=False, ready_event=None):
    from .key_probe import acquire, RelationshipRevokedError
    selected = load(directory / "selected-person.dpapi")
    status_path = directory / "key-listener-status.json"
    old = json.loads(status_path.read_text()) if status_path.exists() else {}
    next_request = old.get("next_request_unix", 0)
    if type(next_request) is not int or next_request < 0:
        raise ValueError("Invalid saved key request deadline")
    deadline = time.monotonic() + duration
    failures, windows = 0, 0
    status = {"stage": "key_listener", "live_collection_ready": False, "success": False,
              "automatic_login": False, "state": "starting", "next_request_unix": next_request,
              "process_id": os.getpid()}
    while time.monotonic() < deadline:
        if ready_event is not None:
            ready_event.clear()
        if not selection_ready(directory, database, selected):
            status.update(state="stopped", reason="selection_changed_or_paused")
            break
        now = time.time()
        next_request = int(next_request_allowed(directory, now, next_request))
        gate = auth_cooldown.active(directory, now=now)
        if gate:
            status.update(state="waiting", reason="account_cooldown", next_request_unix=next_request)
            write_status(status_path, status)
            await asyncio.sleep(min(10, max(0, deadline - time.monotonic())))
            continue
        request = request_missing and not (directory / "people-key.dpapi").exists() and now >= next_request
        if request:
            # Persist before starting, including failed attempts and interruptions.
            next_request = int(now) + 1800
        remaining = deadline - time.monotonic()
        if remaining < 10:
            break
        listen_seconds = min(1800, int(remaining))
        if request_missing and not request and not (directory / "people-key.dpapi").exists() and next_request > now:
            listen_seconds = min(listen_seconds, max(10, int(next_request - now)))
        status.update(state="listening", next_request_unix=next_request, request_missing_key=request,
                      window_started_utc=auth_cooldown.utc_text(now),
                      heartbeat_utc=auth_cooldown.utc_text(now), receiver_identity_verified=False,
                      transport_packets=0, key_messages_received=0,
                      reason="receiving_key_updates" if (directory / "people-key.dpapi").exists() else "waiting_for_sharing_key")
        status.pop("error_type", None)
        write_status(status_path, status)
        trace, details = AuthTrace(), {}
        task = asyncio.create_task(acquire(directory, trace, details, wait_seconds=listen_seconds,
                    native_context=True, listen_only=not request, receive_updates=True, ready_event=ready_event))
        heartbeat = time.monotonic()
        try:
            while not task.done():
                done, _ = await asyncio.wait({task}, timeout=min(10, max(0.1, deadline - time.monotonic())))
                if time.monotonic() - heartbeat >= 30:
                    heartbeat = time.monotonic()
                    status.update(heartbeat_utc=auth_cooldown.utc_text(time.time()),
                        receiver_identity_verified=details.get("receiver_identity_verified") is True,
                        transport_packets=details.get("apns_transport", {}).get("packets_received", 0),
                        key_messages_received=details.get("key_messages_received", 0))
                    for name in ("searchparty_response", "ngm_validation"):
                        if name in details:
                            status[name] = details[name]
                    write_status(status_path, status)
                if not done and (time.monotonic() >= deadline or not selection_ready(directory, database, selected)):
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    status.update(state="stopped", reason="deadline_or_selection_changed")
                    write_status(status_path, status)
                    return status
            result = task.result()
            failures = 0
            status.update(success=result.get("people_key_received") is True,
                          people_key_received=result.get("people_key_received") is True,
                          key_changed=details.get("key_changed", False), state="key_received")
            if stop_after_key and status["success"]:
                break
        except RelationshipRevokedError:
            if database is not None and database.exists():
                with store.connect(database, write=True) as db:
                    sid = store.subject(db, selected["alias"])["id"]
                    db.execute("UPDATE subjects SET active=0 WHERE id=?", (sid,))
            status.update(state="needs_attention", reason="sharing_relationship_unavailable")
            break
        except Exception as error:
            if type(error).__name__ == "KeyAcquisitionTimeout":
                failures = 0
                status.update(state="waiting", reason="key_delivery_pending")
            else:
                failure = trace.failure(error)
                auth_cooldown.record(directory, failure)
                failures = min(failures + 1, 16)
                status.update(state="waiting", reason="transport_or_service_unavailable", error_type=type(error).__name__)
                if trace.http_status in (401, 403) or isinstance(error, (ValueError, KeyError, TypeError)):
                    status.update(state="needs_attention", reason="authentication_or_binding_requires_attention")
                    break
                transient = (isinstance(error, (OSError, TimeoutError)) or
                    type(error).__name__ in {"EndOfStream", "BrokenResourceError", "ClosedResourceError",
                        "ClientConnectionError", "ClientConnectorError", "ClientOSError"} or
                    trace.http_status in (429, 500, 502, 503, 504))
                if not transient:
                    status.update(state="needs_attention", reason="receiver_protocol_requires_attention")
                    break
        finally:
            if ready_event is not None:
                ready_event.clear()
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            status["last_window"] = {name: details[name] for name in (
                "receiver_identity_verified", "selected_relationship_current", "key_distribution_requested",
                "key_distribution_request_accepted", "searchparty_response", "key_messages_received",
                "key_rejection_categories", "ngm_validation", "apns_transport") if name in details}
            status["key_messages_received"] = details.get("key_messages_received", 0)
            status["transport_packets"] = details.get("apns_transport", {}).get("packets_received", 0)
        windows += 1
        status["windows_finished"] = windows
        status["next_request_unix"] = int(next_request_allowed(directory, time.time(), next_request))
        write_status(status_path, status)
        await asyncio.sleep(min(300, 60 * 2 ** min(failures, 5), max(0, deadline - time.monotonic())))
    if status["state"] in ("waiting", "listening") or (status["state"] == "key_received" and not stop_after_key):
        status.update(state="stopped", reason="bounded_listening_window_finished")
    write_status(status_path, status)
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--db", type=Path)
    parser.add_argument("--duration", type=int, default=3600)
    parser.add_argument("--request-missing", action="store_true")
    parser.add_argument("--stop-after-key", action="store_true")
    args = parser.parse_args()
    if not 10 <= args.duration <= 86400:
        parser.error("Duration must be 10-86400 seconds")
    logging.disable(logging.CRITICAL)
    try:
        with collector_lock(args.state_dir / "key-receiver.lock"):
            result = asyncio.run(run(args.state_dir.resolve(), args.db.resolve() if args.db else None,
                duration=args.duration, request_missing=args.request_missing, stop_after_key=args.stop_after_key))
    except (Exception, KeyboardInterrupt) as error:
        result = {"stage": "key_listener", "success": False, "state": "needs_attention",
                  "error_type": type(error).__name__, "live_collection_ready": False}
    print(json.dumps(result, indent=2))
    return 0 if result.get("success") else 2


if __name__ == "__main__":
    raise SystemExit(main())
