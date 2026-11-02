"""One selected-person report fetch, first verified live on 2026-10-28.

The native SecureLocation fields and Date encoding are checked strictly. Unknown
formats fail closed. Coordinates stay in process, DPAPI, or an explicitly named
ledger; diagnostic output contains counts, age, and accuracy only.
"""
import argparse
import asyncio
import base64
import json
import logging
import math
import plistlib
import time
from datetime import datetime, timezone
from pathlib import Path

from location_ledger import store
from .auth_cooldown import active as auth_backoff, record as record_auth_backoff
from .auth_diagnostics import AuthTrace
from .fmf_client import FriendsClient, following
from .key_probe import searchparty, selected_relationship, validate_saved_key
from .report_codec import decrypt_report
from .saved_session import restore
from .searchparty_backoff import active as service_backoff
from .windows_secrets import load, save_atomic

APPLE_EPOCH = 978307200


class LocationReportError(Exception):
    pass


def decoded_observation(plaintext, expected_fm_id):
    if not isinstance(plaintext, bytes) or len(plaintext) > 1024 * 1024:
        raise LocationReportError("Invalid plaintext size")
    try:
        if plaintext.startswith((b"bplist", b"<?xml", b"<plist")):
            data = plistlib.loads(plaintext)
        else:
            data = json.loads(plaintext)
    except (ValueError, UnicodeError, plistlib.InvalidFileException, OverflowError):
        raise LocationReportError("Unknown plaintext encoding") from None
    if not isinstance(data, dict) or data.get("findMyId") != expected_fm_id:
        raise LocationReportError("Report is not bound to the selected participant")
    try:
        lat = store.number(data["latitude"], -90, 90, "latitude")
        lon = store.number(data["longitude"], -180, 180, "longitude")
        accuracy = store.number(data["horizontalAccuracy"], 0, 1_000_000, "accuracy")
        stamp = data["timestamp"]
        if isinstance(stamp, datetime):
            # plistlib's default naive dates represent UTC, never local time.
            stamp = stamp.replace(tzinfo=timezone.utc) if stamp.tzinfo is None else stamp
            observed = math.floor(stamp.timestamp())
        elif type(stamp) in (int, float) and math.isfinite(stamp):
            # Swift Date's default JSON Codable representation is seconds since
            # 2001. Do not guess units from magnitude or use HTTP receipt time.
            observed = math.floor(stamp + APPLE_EPOCH)
        else:
            raise ValueError("Unsupported source timestamp")
        observed = store.epoch(observed)
    except (KeyError, TypeError, ValueError, OverflowError):
        raise LocationReportError("Missing or invalid native location fields") from None
    return {"observed_at": observed, "latitude": lat, "longitude": lon,
            "accuracy_m": accuracy, "source": "findmy-people"}


def newest_observation(response, advertised_id, private_key, fm_id, *, received_at, max_age=900, accept_delayed=False):
    rows = response.get("locationPayload")
    if not isinstance(rows, list) or len(rows) > 256:
        raise LocationReportError("Invalid report collection")
    observations = []
    for row in rows:
        if not isinstance(row, dict) or row.get("id") != advertised_id:
            continue
        infos = row.get("locationInfo")
        if not isinstance(infos, list) or len(infos) > 256:
            raise LocationReportError("Invalid report list")
        for info in infos:
            if not isinstance(info, dict) or info.get("fmt", 0) != 0:
                continue  # Satellite/message formats are not ordinary fixes.
            encoded = info.get("location")
            if not isinstance(encoded, str) or len(encoded) > 1_400_000:
                raise LocationReportError("Invalid encrypted report")
            try:
                payload = base64.b64decode(encoded, validate=True)
                plaintext = decrypt_report(payload, private_key)
            except Exception:
                raise LocationReportError("Encrypted report verification failed") from None
            observations.append(decoded_observation(plaintext, fm_id))
    if not observations:
        return None, {"matching_reports": 0, "reason": "no_matching_encrypted_report"}
    newest = max(observations, key=lambda item: item["observed_at"])
    if any(item["observed_at"] == newest["observed_at"] and item != newest for item in observations):
        raise LocationReportError("Conflicting reports at one source timestamp")
    age = received_at - newest["observed_at"]
    status = {"matching_reports": len(observations), "source_age_seconds": age,
              "source_observed_at_utc": store.iso(newest["observed_at"]),
              "accuracy_m": newest["accuracy_m"], "report_authenticated": True}
    if age < -300:
        return None, {**status, "reason": "source_timestamp_in_future"}
    if age > max_age:
        if accept_delayed and age <= 86400:
            return newest, {**status, "report_is_fresh": False, "reason": "delayed_authenticated_observation"}
        return None, {**status, "reason": "source_report_stale"}
    return newest, {**status, "report_is_fresh": True}


async def probe(directory, trace, result, *, database=None, max_age=900, accept_delayed=False, capture_encrypted=False,
                ignore_503_backoff=False):
    directory = Path(directory)
    for pause in (auth_backoff(directory), service_backoff(directory, ignore_503=ignore_503_backoff)):
        if pause:
            result.update(pause)
            return
    key_path = directory / "people-key.dpapi"
    if not key_path.exists():
        result.update(reason="verified_people_key_required", network_request_attempted=False)
        return
    selection, key = load(directory / "selected-person.dpapi"), load(key_path)
    if key.get("sender_authenticated") is not True:
        raise LocationReportError("Verified selection and sharing key required")
    state, provider = restore(directory)
    client = FriendsClient(state, provider, trace, native_context=True)
    try:
        dsid = client.login["dsid"]
        try:
            private_key = validate_saved_key(key, selection, dsid=dsid, device_id=client.device_id)
        except (KeyError, TypeError, ValueError):
            raise LocationReportError("Selection, verified key, account, and device must match") from None
        apns = load(directory / "apns.dpapi")
        if apns.get("device_id") != client.device_id:
            raise LocationReportError("Push identity mismatch")
        alias = store.text_label(selection["alias"], "Participant alias")
        if database is not None and Path(database).exists():
            with store.connect(database) as db:
                store.subject(db, alias, require_active=True)
        client.apns_token = apns["courier_token"].upper()
        trace.enter("searchparty_fetch")
        result["network_request_attempted"] = True
        relationship = selected_relationship(selection, dsid, following(await client.request()))
        reply = await searchparty(client, relationship.fm_id, state_dir=directory, advertised_id=key["advertised_id"],
                                  intent="startLocationUpdates", mode="shallow",
                                  stats=result.setdefault("searchparty_response", {}), ignore_503_backoff=ignore_503_backoff)
        received_at = int(time.time())
        if capture_encrypted and isinstance(reply.get("locationPayload"), list):
            selected_payload = [{"id": row["id"], "locationInfo": row.get("locationInfo")}
                for row in reply["locationPayload"] if isinstance(row, dict) and row.get("id") == key["advertised_id"]]
            save_atomic(directory / "latest-encrypted-report.dpapi", {
                "account_dsid": dsid, "device_id": client.device_id, "fm_id": relationship.fm_id,
                "received_at": received_at, "response": {"locationPayload": selected_payload}})
            result["encrypted_response_cached"] = True
        observation, diagnostics = newest_observation(reply, key["advertised_id"], private_key,
                                                       relationship.fm_id, received_at=received_at, max_age=max_age,
                                                       accept_delayed=accept_delayed)
        result.update(diagnostics)
        if observation is None:
            return
        if load(directory / "selected-person.dpapi") != selection:
            raise LocationReportError("Selection changed during this request")
        fresh = diagnostics["report_is_fresh"]
        # Only a fresh authenticated report establishes the collector's bootstrap
        # milestone. A delayed fix can enter history without replacing that proof.
        if fresh:
            save_atomic(directory / "latest-fix.dpapi", {"account_dsid": dsid, "fm_id": relationship.fm_id,
                        "received_at": received_at, "observation": observation})
        result.update(success=True, fresh_report_received=fresh, delayed_report_received=not fresh,
                      encrypted_preview_saved=fresh, live_collection_ready=fresh)
        if database is not None:
            if not Path(database).exists():
                store.initialize(database)
                with store.connect(database, write=True) as db:
                    store.register(db, alias)
            with store.connect(database, write=True) as db:
                inserted = store.ingest(db, alias, observation, received_at=received_at)
            result.update(ledger_written=True, new_observation=inserted)
    finally:
        await client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--db", type=Path, help="Optionally store this validated fix in a local ledger")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    trace = AuthTrace()
    result = {"stage": "selected_location_probe", "success": False, "fresh_report_received": False,
              "automatic_retry": False, "live_collection_ready": False}
    try:
        asyncio.run(probe(args.state_dir, trace, result, database=args.db, capture_encrypted=True))
    except (Exception, KeyboardInterrupt) as error:
        result.update(trace.failure(error))
        result["stage"] = "selected_location_probe"
        if isinstance(error, LocationReportError):
            result.update(error_type="LocationReportError", reason="report_or_binding_validation_failed")
        pause = record_auth_backoff(args.state_dir, result)
        if pause:
            result["retry_not_before_utc"] = pause["retry_not_before_utc"]
    (args.state_dir / "location-status.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result.get("success") else 2


if __name__ == "__main__":
    raise SystemExit(main())
