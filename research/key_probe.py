"""Bounded authenticated key acquisition for the locally selected participant."""
import argparse
import asyncio
import base64
import json
import logging
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from functools import partial

from aiohttp import BasicAuth

from .auth_cooldown import active, record
from .auth_diagnostics import AuthTrace, status_number
from .fmf_client import FriendsClient, following
from .ids_probe import install_verified_transport
from .push_receiver import verified_connection
from .report_codec import decode_private_key
from .saved_session import restore
from . import searchparty_backoff
from .searchparty_backoff import SearchPartyError
from .windows_secrets import load, save_atomic, save_new


class RelationshipRevokedError(ValueError):
    """The selected accepted relationship is absent from a current server response."""


def selected_relationship(selection, dsid, rows):
    if selection.get("account_dsid") != dsid:
        raise ValueError("Participant selection does not authorize this account")
    wanted = selection["relationship"]["fm_id"]
    matches = [row for row in rows if row["fm_id"] == wanted]
    if len(matches) != 1:
        raise RelationshipRevokedError("Selected relationship is no longer accepted")
    row = matches[0]
    return SimpleNamespace(fm_id=row["fm_id"], accepted_handles=tuple(row["handles"]),
                           secure_locations_capable=row["secure_locations_capable"],
                           fallback_to_legacy_allowed=row["legacy_fallback_allowed"])


def searchparty_summary(response, *, selected_id=None):
    """Service shape and numeric statuses only; never report IDs or ciphertext."""
    known = {"statusCode", "configVersion", "locationPayload", "failedFmIds", "results", "fetch", "errors", "serverContext"}
    summary = {"known_fields": sorted(known.intersection(response)), "other_field_count": len(set(response) - known)}
    failed = response.get("failedFmIds")
    if isinstance(failed, list):
        summary["failed_participant_count"] = len(failed)
        if selected_id is not None:
            summary["selected_participant_failed"] = selected_id in failed
    for field in ("locationPayload", "results", "fetch", "errors"):
        rows = response.get(field)
        if isinstance(rows, list):
            summary[field + "_count"] = len(rows)
            codes = []
            for row in rows[:100]:
                if not isinstance(row, dict):
                    continue
                value = row.get("statusCode", row.get("status"))
                if isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) < 7:
                    value = int(value)
                if status_number(value) is not None:
                    codes.append(value)
            if codes:
                summary[field + "_statuses"] = codes
    return summary


async def searchparty(client, fm_id, *, state_dir, advertised_id=None, intent="distributeKeys", mode="proactive", api_version=1, stats=None,
                      ignore_503_backoff=False):
    if searchparty_backoff.active(state_dir, ignore_503=ignore_503_backoff):
        raise SearchPartyError("SearchParty backoff is active")
    if intent not in {"distributeKeys", "startLocationUpdates"} or mode not in {"proactive", "shallow"}:
        raise ValueError("Unsupported SearchParty operation")
    if api_version not in (1, 4):
        raise ValueError("Unsupported SearchParty API version")
    headers = await client.provider.get_headers(client.provider.account_ids["uid"], client.device_id, force_refresh=True)
    headers = {key: value for key, value in headers.items() if key.lower() != "x-mme-client-info"}
    headers.update({"Accept": "application/json", "accept-version": str(api_version), "Content-Type": "application/json",
                    "User-Agent": f"searchpartyuseragent/1 {client.product}/{client.os_version}",
                    "X-MMe-Client-Info": f"<{client.product}> <macOS;{client.os_version};{client.build}> <com.apple.icloud.searchpartyuseragent/1.0>",
                    "x-apple-i-device-type": "1", "x-apple-setup-proxy-request": "true"})
    body = {"fetch": [{"fmId": fm_id, "intent": intent, "mode": mode,
                       "ids": [] if advertised_id is None else [advertised_id]}],
            "clientContext": {"apsToken": client.apns_token, "clientId": client.device_id,
                              "contextApp": "com.apple.findmy.findmylocated",
                              "shallowStats": {}, "liveStats": {}, "nearbyWatchIdentifiers": []}}
    if stats is not None:
        stats["client_identifier_case_preserved"] = True
    token = client.login["mobileme_data"]["tokens"]["searchPartyToken"]
    session = await client.http._get_session()
    if intent == "distributeKeys":
        from .collector import write_status
        sent_at = int(time.time())
        write_status(Path(state_dir) / "key-request-status.json", {
            "request_started_unix": sent_at, "next_bootstrap_request_unix": sent_at + 1800})
    async with session.post("https://gateway.icloud.com/findmyservice/fetch", json=body, headers=headers,
                            auth=BasicAuth(client.login["dsid"], token), ssl=client.http._ssl, allow_redirects=False) as reply:
        client.http.trace.http_response(reply.status, reply.headers.get("Retry-After"))
        delay = client.http.trace.retry_after_seconds
        details = {"http_status": reply.status}
        if delay is not None:
            details["retry_after_seconds"] = delay
        backoff = searchparty_backoff.record(state_dir, details)
        if backoff:
            details["retry_not_before_utc"] = backoff["retry_not_before_utc"]
        if stats is not None:
            stats.update(details)
        if reply.status != 200:
            if stats is not None:
                media = reply.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                stats["response_content_type"] = media if media in {
                    "application/json", "text/html", "text/plain", "application/xml", "text/xml"} else "other"
                stats["server_identifies_apple"] = reply.headers.get("Server", "").strip().lower() == "apple"
                server = reply.headers.get("Server", "").strip().lower()
                stats["server_family"] = next((name for name in ("apple", "nginx", "envoy", "ats", "apache")
                    if server == name or server.startswith(name + "/")), "other")
                try:
                    raw_error = await searchparty_backoff.read_limited(reply.content, 64 * 1024)
                    stats["response_bytes"] = len(raw_error)
                    prefix = raw_error.lstrip().lower()
                    stats["response_format"] = "empty" if not prefix else "html" if prefix.startswith((b"<!doctype html", b"<html")) else "other"
                    # Classify known error pages without retaining any of their
                    # text, request identifiers, cookies, or reflected values.
                    phrases = {"service_unavailable": (b"service unavailable", b"service temporarily unavailable"),
                               "rate_limited": (b"rate limit", b"too many requests"),
                               "access_denied": (b"access denied", b"forbidden"),
                               "upstream_connection_failure": (b"upstream connect error", b"connection failure")}
                    stats["error_page_categories"] = [name for name, markers in phrases.items()
                        if any(marker in prefix for marker in markers)]
                    try:
                        error_body = json.loads(raw_error)
                    except (ValueError, UnicodeError):
                        pass
                    else:
                        stats["response_format"] = "json"
                        if isinstance(error_body, dict):
                            code = error_body.get("statusCode")
                            if isinstance(code, str) and code.isascii() and code.isdecimal() and len(code) < 7:
                                code = int(code)
                            if status_number(code) is not None:
                                stats["service_status"] = code
                except (SearchPartyError, OSError, TimeoutError):
                    stats["error_body_unavailable_or_oversized"] = True
            raise SearchPartyError("SearchParty request was rejected")
        raw = await searchparty_backoff.read_limited(reply.content, 4 * 1024 * 1024)
        try:
            response = json.loads(raw)
        except (ValueError, UnicodeError):
            raise SearchPartyError("SearchParty returned invalid JSON") from None
        if isinstance(response, dict) and stats is not None:
            stats.update(searchparty_summary(response, selected_id=fm_id))
        if not isinstance(response, dict) or str(response.get("statusCode")) != "200":
            raise SearchPartyError("SearchParty service returned a failure")
        failed = response.get("failedFmIds")
        failed = [] if failed is None else failed
        if not isinstance(failed, list) or fm_id in failed:
            raise SearchPartyError("SearchParty could not process the selected participant")
        return response


def key_summary():
    return {"stage": "people_key_acquisition", "success": True, "people_key_received": True,
            "sender_authenticated": True, "key_saved_encrypted": True, "live_collection_ready": False}


def key_rejection_category(message):
    """Translate pinned receiver errors; never forward exception text."""
    if not isinstance(message, str) or len(message) > 256:
        return "unclassified"
    return {
        "IDS envelope is not pair-ec": "unsupported_encryption",
        "IDS sender does not match selected relationship": "other_sender",
        "IDS target does not match one registered identity": "receiver_binding",
        "IDS directory has no selected sender": "sender_not_in_directory",
        "IDS sender push token is unknown or ambiguous": "sender_device_binding",
        "IDS sender prekey signature is invalid": "sender_prekey_signature",
        "NGM validator mismatch": "ngm_identity_binding",
        "NGM message signature is invalid": "ngm_message_signature",
        "NGM plaintext padding is malformed": "ngm_plaintext_padding",
        "Find My message type or version is unsupported": "unsupported_application_message",
        "Find My key payload is malformed": "malformed_key_payload",
        "Find My key payload root is not an array": "unsupported_key_container",
        "Find My key payload has wrong relationship": "other_relationship",
        "Find My advertised identifier is malformed": "malformed_advertised_identifier",
    }.get(message, "unclassified")


def validate_saved_key(key, selection, *, dsid, device_id):
    """Require the saved verification and all current identity bindings."""
    if (selection.get("account_dsid") != dsid
            or key.get("sender_authenticated") is not True
            or key.get("account_dsid") != dsid
            or key.get("device_id") != device_id
            or key.get("fm_id") != selection["relationship"]["fm_id"]):
        raise ValueError("Sharing key does not match the authorized selection and receiver")
    if len(base64.b64decode(key["advertised_id"], validate=True)) != 32:
        raise ValueError("Invalid advertised identifier")
    return decode_private_key(base64.b64decode(key["private_key_blob"], validate=True))


async def prepare_key_request(client, selection, dsid, state_dir, trace, stats, *, api_version=1, listen_only=False):
    trace.enter("people_key_request")
    response = await client.request()
    relationship = selected_relationship(selection, dsid, following(response))
    stats["selected_relationship_current"] = True
    if listen_only:
        stats["key_distribution_requested"] = False
    else:
        await client.request(refresh=True)
        await client.request(selected=relationship.fm_id)
        stats["key_distribution_requested"] = True
        try:
            response = await searchparty(client, relationship.fm_id, state_dir=state_dir, api_version=api_version,
                                        stats=stats.setdefault("searchparty_response", {}))
        except SearchPartyError:
            details = stats.get("searchparty_response", {})
            if details.get("http_status") not in (429, 503):
                raise
            record(state_dir, details)
            stats["key_distribution_request_accepted"] = False
            stats["receiving_despite_gateway_rejection"] = True
            # A queued, authenticated key is still usable. Keep the subscribed
            # streams alive instead of dropping messages already queued while
            # this gateway request was in flight. Saved backoffs remain active.
        else:
            stats["key_distribution_request_accepted"] = True
            stats["searchparty_status"] = int(response["statusCode"])
    trace.enter("people_key_wait")
    return relationship


def save_delivery(state_dir, selection, delivery, *, dsid, device_id, replace_existing=False):
    if load(state_dir / "selected-person.dpapi") != selection:
        raise ValueError("Participant selection changed during the request")
    decode_private_key(delivery.private_key_blob)
    replacement = {"account_dsid": dsid, "device_id": device_id,
        "fm_id": selection["relationship"]["fm_id"], "advertised_id": delivery.advertised_id,
        "private_key_blob": base64.b64encode(delivery.private_key_blob).decode("ascii"),
        "saved_at": time.time(), "sender_authenticated": True}
    validate_saved_key(replacement, selection, dsid=dsid, device_id=device_id)
    path = state_dir / "people-key.dpapi"
    if replace_existing and path.exists():
        previous = load(path)
        validate_saved_key(previous, selection, dsid=dsid, device_id=device_id)
        if (previous["advertised_id"], previous["private_key_blob"]) == (replacement["advertised_id"], replacement["private_key_blob"]):
            return False
        if previous["advertised_id"] == replacement["advertised_id"]:
            raise ValueError("One advertised identifier has conflicting sharing keys")
        save_atomic(state_dir / "previous-people-key.dpapi", previous)
        save_atomic(path, replacement)
    else:
        save_new(path, replacement)
    return True


async def acquire(state_dir, trace, stats, *, wait_seconds=45, native_context=False, api_version=1, listen_only=False,
                  receive_updates=False, ready_event=None):
    backoff = searchparty_backoff.active(state_dir)
    if backoff and not listen_only:
        return backoff
    trace.enter("people_key_setup")
    state_dir = Path(state_dir).resolve()
    config = json.loads((state_dir / "push-helper-config.json").read_text())
    if config["onitrack_commit"] != "04dd25312643d8c9aa93c883a343488a4b682635":
        raise ValueError("Unexpected key protocol implementation")
    sys.path.insert(0, config["onitrack_path"])
    from onitrack import ids, key_acquisition as protocol
    from .key_subscription import subscribed_acquirer_class
    PeopleKeyAcquirer = subscribed_acquirer_class(protocol)
    install_verified_transport(ids, trace)
    state, provider = restore(state_dir)
    client = FriendsClient(state, provider, trace, native_context=native_context)
    stats["native_context_experiment"] = native_context
    stats["searchparty_api_version"] = api_version
    stats["listen_only"] = listen_only
    try:
        context_path = state_dir / "fmf-context.dpapi"
        if native_context and context_path.exists():
            saved_context = load(context_path)
            if (saved_context.get("account_dsid") != client.login["dsid"]
                    or saved_context.get("device_id") != client.device_id):
                raise ValueError("Friends context belongs to another account or machine")
            client_id = saved_context.get("server_context", {}).get("clientId")
            if not isinstance(client_id, str) or not client_id:
                raise ValueError("Saved Friends context has no client identifier")
            # Keep only the server-issued session identifier, not stale deltas.
            client.server_context = {"clientId": client_id}
            stats["server_client_context_seeded"] = True
        selection = load(state_dir / "selected-person.dpapi")
        dsid = state["login"]["data"]["dsid"]
        if selection.get("account_dsid") != dsid:
            raise ValueError("Participant selection is not authorized for this account")
        key_path = state_dir / "people-key.dpapi"
        if key_path.exists():
            key = load(key_path)
            validate_saved_key(key, selection, dsid=dsid, device_id=client.device_id)
            if not receive_updates:
                return key_summary()
        registered, apns = load(state_dir / "ids.dpapi"), load(state_dir / "apns.dpapi")
        if not registered.get("registered") or any(item.get("device_id") != client.device_id for item in (registered, apns)):
            raise ValueError("Registered push and IDS identities do not match")
        await asyncio.to_thread(ids._bag, "id-query")
        loop = asyncio.get_running_loop()

        async def prepare(base_token):
            # The upstream callback runs after all key-topic streams exist.
            await acquirer.finish_receiver_preflight()
            client.apns_token = base_token.hex().upper()
            relationship = await prepare_key_request(client, selection, dsid, state_dir, trace, stats,
                                                      api_version=api_version, listen_only=listen_only)
            if ready_event is not None:
                ready_event.set()
            return relationship

        def prepare_delivery(base_token):
            future = asyncio.run_coroutine_threadsafe(prepare(base_token), loop)
            try:
                return future.result(timeout=90)
            except BaseException:
                future.cancel()
                raise

        def accept_delivery(delivery):
            stats["key_changed"] = save_delivery(state_dir, selection, delivery, dsid=dsid,
                device_id=client.device_id, replace_existing=receive_updates)

        def diagnostic(step, fields):
            if step == "people_key_subscribed":
                stats["push_topics_subscribed"] = status_number(fields.get("topic_count"))
                stats["push_token_changed"] = fields.get("token_changed") is True
            elif step == "apns_notification_received":
                stats["notifications_received"] = stats.get("notifications_received", 0) + 1
                command = status_number(fields.get("command"))
                if command is not None:
                    counts = stats.setdefault("notification_commands", {})
                    label = str(command)
                    counts[label] = counts.get(label, 0) + 1
                if fields.get("command") == 242:
                    stats["key_messages_received"] = stats.get("key_messages_received", 0) + 1
            elif step == "people_key_delivery_rejected":
                stats["key_messages_rejected"] = stats.get("key_messages_rejected", 0) + 1
                category = key_rejection_category(fields.get("category"))
                counts = stats.setdefault("key_rejection_categories", {})
                counts[category] = counts.get(category, 0) + 1
            elif step == "ids_receiver_preflight":
                stats["receiver_identity_verified"] = fields.get("status") == "ready"
            elif step == "ids_sender_preflight":
                stats["sender_identity_count"] = status_number(fields.get("identity_count"))
                stats["sender_ngm_identity_count"] = status_number(fields.get("ngm_identity_count"))
            # Never forward the upstream debug dictionary: it can contain tokens.

        acquirer = PeopleKeyAcquirer(people_state={"ids": registered, "apns": apns},
                    user_agent=f"[macOS,{client.os_version},{client.build},{client.product}]",
                    debug_emit=diagnostic, connection_factory=partial(verified_connection,
                        stats=stats.setdefault("apns_transport", {})), receiver_preflight=True)
        from .ngm_compat import compatible_validator
        with compatible_validator(ids, protocol, stats):
            async with asyncio.timeout(wait_seconds + 120):
                await acquirer.acquire(wait_seconds=wait_seconds, prepare_delivery=prepare_delivery, accept_delivery=accept_delivery)
        return key_summary()
    finally:
        await client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--wait-seconds", type=int, default=45)
    parser.add_argument("--listen-only", action="store_true", help="Check the relationship and receive pending keys without a SearchParty request")
    parser.add_argument("--native-context", action="store_true", help="Experimental findmylocated client and MobileMe server context")
    parser.add_argument("--api-version", type=int, choices=(1, 4), default=1)
    args = parser.parse_args()
    if not 10 <= args.wait_seconds <= (1800 if args.listen_only else 90):
        parser.error("Wait must be 10-90 seconds, or 10-1800 seconds for --listen-only")
    logging.disable(logging.CRITICAL)
    trace, stats = AuthTrace(), {}
    try:
        cooldown = active(args.state_dir)
        if cooldown:
            print(json.dumps(cooldown, indent=2))
            return 2
        from .collector import collector_lock
        with collector_lock(args.state_dir / "key-receiver.lock"):
            result = asyncio.run(acquire(args.state_dir, trace, stats, wait_seconds=args.wait_seconds,
                                        native_context=args.native_context, api_version=args.api_version, listen_only=args.listen_only))
    except (Exception, KeyboardInterrupt) as error:
        result = trace.failure(error)
        result["stage"] = "people_key_acquisition"
        if type(error).__name__ == "KeyAcquisitionTimeout":
            result.update({"reason": "key_delivery_pending", "error_type": "KeyAcquisitionTimeout"})
        cooldown = record(args.state_dir, result)
        if cooldown:
            result["retry_not_before_utc"] = cooldown["retry_not_before_utc"]
    result.update(stats)
    (args.state_dir / "key-status.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result.get("success") else 2


if __name__ == "__main__":
    raise SystemExit(main())
