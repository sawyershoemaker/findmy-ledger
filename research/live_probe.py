"""Bounded, selected-participant native Live setup diagnostic.

This is deliberately separate from the installed snapshot collector. Its
redacted status never includes handles, device identifiers, keys, or locations.
"""
import argparse
import asyncio
import base64
from contextlib import AsyncExitStack
import json
import logging
from pathlib import Path
import plistlib
import sys
import time
from uuid import uuid4

from location_ledger import store
from .auth_cooldown import active as auth_backoff
from .auth_diagnostics import AuthTrace
from .collector import collector_lock, write_status
from .fmf_client import FriendsClient, following
from .ids_probe import install_verified_transport
from .key_probe import selected_relationship, validate_saved_key
from .push_receiver import verified_connection
from .saved_session import restore
from .windows_secrets import load, save_atomic
from .live_signaling import (SelectedPeer, allocation_request, invitation,
    cancellation, seal_message, session_envelope, TOPIC, RELAY_TOPIC, USER_AGENT)
from .ngm_compat import compatible_validator
from .live_relay import RelayBinding
from .ngm_replay import reserve_counter
from .live_tcp import ControlTCP
from .live_pair import private_identity, public_identity
from .live_utun import UTunSession
from .live_payload import decode as decode_live, heartbeat
from .location_probe import LocationReportError

CAPABILITIES = ("supports-beacon-sharing-v2", "supports-beacon-sharing-v3",
                "supports-secure-loc-v1", "supports-fmd-v2",
                "supports-incoming-fmd-v1", "supports-findmy-plugin-messages")


async def shutdown_channels(relay, channels, result):
    """Close the native application before cancelling its IDS transport.

    A lingering session can stop the account-scoped location monitor after a
    replacement starts. The native T=-3 message releases that session promptly.
    Cleanup remains bounded when the peer or relay has gone away.
    """
    if relay is None or not channels:
        return
    try:
        async with asyncio.timeout(2):
            payload = heartbeat(-3)
            for channel in channels.values():
                await relay.send_data(channel.encrypt(payload))
        result["application_shutdown_sent"] = True
    except (OSError, TimeoutError, ValueError):
        result["application_shutdown_failed"] = True


async def session_setup(connection, streams, ids, protocol, registered, token,
                        own_handle, peer, directory, result, *, observe_transport=False,
                        duration=60, capture=True, decode_payload=None, on_observation=None,
                        on_tick=None, on_key=None, quiet_after=300):
    from pypush.apns.protocol import SendMessageCommand
    session_id, participant_id = uuid4(), uuid4()
    request = allocation_request(session_id, own_handle, peer)
    outgoing = {request["U"]}
    relay_packets, relay_messages, delivery_errors = [], [], []
    tcp_frames = []
    control_plain, application_payloads = [], []
    tcp = ControlTCP()
    rows = load(directory / "live-directory.dpapi")["rows"]
    entry = plistlib.loads(base64.b64decode(rows[0]["entry_bplist"]))
    if entry.get("push-token") != peer.identity.push_token or rows[0]["handle"] != peer.handle:
        raise ValueError("Control identity does not match selected device")
    utun = UTunSession(session_id, private_identity(registered["identity"]),
        public_identity(entry["client-data"]["public-message-identity-key"]), registered["device_id"])
    relay = None
    def capture_save(path, value):
        if capture:
            save_atomic(path, value)

    def append_status(name, value, limit=32):
        values = result.setdefault(name, [])
        if len(values) < limit:
            values.append(value)

    async def send(topic, body):
        await connection._send(SendMessageCommand(topic=topic, token=token,
            payload=plistlib.dumps(body, fmt=plistlib.FMT_BINARY),
            id=body["i"].to_bytes(4, "big"), outgoing=True))
    async def signal(command, value):
        sender_key = protocol._load_ec_private_key(registered["identity"]["device_private_key_pem"], "local signing key")
        counter = reserve_counter(directory / "ngm-replay.dpapi", ids._compact_public_key(sender_key),
            peer.identity.device_public_key.public_numbers().x.to_bytes(32, "big"),
            peer.identity.prekey_public_key.public_numbers().x.to_bytes(32, "big"))
        encrypted = seal_message(ids, registered["identity"], peer.identity,
                                 plistlib.dumps(value, fmt=plistlib.FMT_BINARY), counter=counter)
        body = session_envelope(command, own_handle, peer, encrypted)
        outgoing.add(body["U"])
        await send(TOPIC, body)
    result["phase"] = "relay_and_invitation"
    started = time.monotonic()
    pending = {asyncio.create_task(stream.receive()): topic for topic, stream in streams.items()}
    sent = False
    try:
        await send(RELAY_TOPIC, request)
        result["relay_allocation_sent"] = True
        await signal(232, invitation(session_id, participant_id, peer))
        sent = True
        result["invitation_sent"] = True
        deadline = asyncio.get_running_loop().time() + duration
        last_tick, last_heartbeat, last_application, last_connect = started, started, started, started
        last_location, newest_source = started, None
        control_ids = []
        while pending:
            now = time.monotonic()
            if now - last_tick >= 1:
                last_tick = now
                if on_tick is not None:
                    await on_tick()
                if relay is not None:
                    for packet in tcp.retransmit(now):
                        await relay.send_data(packet)
                    if (not relay.received_connected_ack and relay.channel is not None
                            and now-last_connect >= 3 and now-started <= 60):
                        last_connect = now
                        await relay.start_control()
                if relay is not None and utun.channels and now - last_heartbeat >= 30:
                    last_heartbeat = now
                    for channel in utun.channels.values():
                        await relay.send_data(channel.encrypt(heartbeat(-1)))
                    result["heartbeats_sent"] = result.get("heartbeats_sent", 0) + 1
                if tcp.closed:
                    raise ConnectionError("Native control stream ended")
                if now - last_application > 210:
                    raise TimeoutError("Native Live peer stopped responding")
                if not utun.channels and now - started > 90:
                    raise TimeoutError("Native Live setup timed out")
                # Heartbeats prove that the peer responds, not that its last
                # coordinates are current. Renew a quiet native session rather
                # than synthesizing stationary observations or polling snapshots.
                if now - last_location >= quiet_after:
                    result.update(phase="live_location_refresh", quiet_session_renewal=True)
                    return
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                break
            done, _ = await asyncio.wait(pending, timeout=min(remaining, 1), return_when=asyncio.FIRST_COMPLETED)
            if not done:
                continue
            for task in done:
                topic = pending.pop(task)
                message = task.result()
                if topic == "relay_udp":
                    pending[asyncio.create_task(relay.receive())] = topic
                    if capture and len(relay_packets) < 64:
                        relay_packets.append(base64.b64encode(message).decode("ascii"))
                        capture_save(directory / "live-relay-packets.dpapi", {
                            "received_at": time.time(), "packets_base64": relay_packets})
                    packet_stage = "relay_control"
                    try:
                        if message[:2] == b"\0\x17":
                            details = await relay.handle_control(message)
                        elif len(message) >= 5 and 0x40 <= message[0] <= 0x7f and message[4] == 0x20:
                            packet_stage = "control_tcp"
                            replies, frames = tcp.receive(relay.channel_payload(message))
                            for reply in replies:
                                await relay.send_data(reply)
                            details = {"kind": "control_tcp", "bytes": len(message),
                                "authenticated": False, "tcp_checksum_valid": True,
                                "established": tcp.established, "closed": tcp.closed,
                                "replies_sent": len(replies), "frames_received": len(frames),
                                "frame_sizes": [len(f) for f in frames]}
                            for frame in frames:
                                packet_stage = "pair_control"
                                if len(tcp_frames) < 32:
                                    tcp_frames.append(base64.b64encode(frame).decode("ascii"))
                                outgoing_frames, control_status, control_data = utun.receive_control(frame)
                                append_status("utun_controls", control_status)
                                if len(control_plain) < 32:
                                    control_plain.append(base64.b64encode(control_data).decode("ascii"))
                                for outgoing_frame in outgoing_frames:
                                    for packet in tcp.send_frame(outgoing_frame):
                                        await relay.send_data(packet)
                            if frames and capture:
                                capture_save(directory / "live-tcp-frames.dpapi", {
                                    "received_at": time.time(), "frames_base64": tcp_frames})
                                capture_save(directory / "live-tcp-decoded.dpapi", {
                                    "received_at": time.time(), "frames_base64": control_plain})
                                capture_save(directory / "live-utun-channels.dpapi", {
                                    "received_at": time.time(), "channels": [{
                                        "request_base64": base64.b64encode(c.request).decode("ascii"),
                                        "reply_base64": base64.b64encode(c.reply).decode("ascii")}
                                        for c in utun.channels.values()]})
                        elif len(message) >= 6 and 0x40 <= message[0] <= 0x7f and message[4:6] == b"\xe0\0":
                            packet_stage = "stream_datagram"
                            channel, index, payload = utun.decrypt_datagram(relay.channel_payload(message))
                            details = {"kind": "utun_datagram", "bytes": len(message),
                                "authenticated": False, "udp_checksum_valid": True,
                                "payload_bytes": len(payload), "is_binary_plist": payload.startswith(b"bplist00")}
                            if decode_payload is not None:
                                packet_stage = "inner_report"
                                received_at = int(time.time())
                                kind, observations, diagnostics = decode_payload(payload, received_at)
                                reports = diagnostics["authenticated_reports"]
                                details.update(T=kind, authenticated=reports > 0)
                                if reports:
                                    channel.mark_authenticated(index)
                                    last_application = now
                                    result["authenticated_reports"] = result.get("authenticated_reports", 0) + reports
                                    result.update(native_live_ready=True, success=True, phase="live_streaming")
                                if kind in (-1, -2, -3):
                                    # Control messages lack report AEAD. Deduplicate separately;
                                    # they cannot consume the authenticated report replay window.
                                    marker = diagnostics["control_id"]
                                    if marker not in control_ids:
                                        control_ids = (control_ids + [marker])[-128:]
                                        last_application = now
                                        result["heartbeat_requests" if kind == -1 else "heartbeat_replies" if kind == -2 else "shutdown_messages"] = result.get(
                                            "heartbeat_requests" if kind == -1 else "heartbeat_replies" if kind == -2 else "shutdown_messages", 0) + 1
                                        if kind == -1:
                                            await relay.send_data(channel.encrypt(heartbeat(-2)))
                                        elif kind == -3:
                                            raise ConnectionError("Native application session ended")
                                for observation in observations:
                                    if newest_source is None or observation["observed_at"] > newest_source:
                                        newest_source = observation["observed_at"]
                                        last_location = now
                                    if on_observation is not None:
                                        on_observation(observation, received_at)
                                    if observation["observed_at"] >= result.get("source_observed_unix", 0):
                                        result.update(source_observed_at_utc=store.iso(observation["observed_at"]),
                                            source_observed_unix=observation["observed_at"],
                                            source_age_seconds=received_at-observation["observed_at"],
                                            accuracy_m=observation["accuracy_m"], last_report_unix=received_at)
                            if payload.startswith(b"bplist00"):
                                app_message = plistlib.loads(payload)
                                if isinstance(app_message, dict):
                                    details["known_fields"] = sorted(set(app_message).intersection({"T", "V", "I", "P"}))
                                    for field in ("T", "V"):
                                        if type(app_message.get(field)) is int:
                                            details[field] = app_message[field]
                            if capture and len(application_payloads) < 64:
                                application_payloads.append(base64.b64encode(payload).decode("ascii"))
                                capture_save(directory / "live-application-payloads.dpapi", {
                                    "received_at": time.time(), "payloads_base64": application_payloads})
                        else:
                            details = relay.packet_summary(message)
                    except (ValueError, LocationReportError) as error:
                        details = {"bytes": len(message), "authenticated": False,
                                   "kind": "rejected_packet", "stage": packet_stage, "error_type": type(error).__name__}
                        categories = {"Unsupported IDS data compression": "compression", "IDS data channel UDP checksum mismatch": "udp_checksum",
                            "Replayed or expired IDS datagram": "replay", "Invalid IDS data channel UDP header": "udp_header",
                            "Invalid IDS stream packet": "stream_size", "Unknown IDS encrypted channel": "unknown_channel",
                            "Control TCP checksum mismatch": "tcp_checksum", "badly formed hexadecimal UUID string": "local_uuid_format"}
                        if str(error) in categories:
                            details["reason"] = categories[str(error)]
                        result["rejected_packets"] = result.get("rejected_packets", 0) + 1
                    if len(result.setdefault("relay_packets", [])) < 64:
                        result["relay_packets"].append(details)
                    continue
                pending[asyncio.create_task(streams[topic].receive())] = topic
                if len(message.payload) > 1024 * 1024:
                    raise ValueError("Oversized session response")
                body = plistlib.loads(message.payload)
                if not isinstance(body, dict):
                    continue
                command = body.get("c")
                if command == 242 and on_key is not None:
                    await on_key(body, topic, connection)
                if type(command) is int:
                    counts = result.setdefault("commands", {})
                    label = str(command) if str(command) in counts or len(counts) < 32 else "other"
                    counts[label] = counts.get(label, 0) + 1
                if command == 120:
                    details = {"topic": topic, "correlated": body.get("fU") in outgoing,
                        "known_fields": sorted(set(body).intersection({"c", "U", "i", "s", "e", "tP", "sP", "E", "P", "status", "reason", "fcn", "t", "fU", "fR", "fRM", "fM"}))}
                    for field in ("s", "status", "reason", "fR"):
                        if type(body.get(field)) is int:
                            details[field] = body[field]
                    if body.get("fRM") == "ec-com.apple.messageprotection-602":
                        details["reason"] = "missing_ngm_replay_counter"
                    if len(delivery_errors) < 16:
                        result.setdefault("delivery_errors", []).append(details)
                        delivery_errors.append(base64.b64encode(message.payload).decode("ascii"))
                        capture_save(directory / "live-delivery-errors.dpapi", {
                            "received_at": time.time(), "responses_bplist": delivery_errors})
                if command == 255 and body.get("U") in outgoing:
                    delivery = {"correlated": True, "relay_topic": topic == RELAY_TOPIC}
                    for field in ("s", "e", "status"):
                        if type(body.get(field)) is int:
                            delivery[field] = body[field]
                    append_status("delivery_responses", delivery)
                if topic == RELAY_TOPIC and body.get("U") == request["U"]:
                    known = {"c", "U", "qids", "qrs", "qec", "qrip", "qrip6", "qrp", "qrst", "qrsk",
                             "qrsi", "qal", "qv", "qri", "link-protocol", "qph3", "qptp", "qsatv",
                             "qr", "qem", "qrsistage", "qe", "qrbv", "qswv", "qrpr", "qia", "qaip", "qaat", "qns", "lw", "ua"}
                    relay_details = {"command": command, "known_fields": sorted(known.intersection(body)),
                        "other_field_count": len(set(body) - known),
                        "session_id_matches": body.get("qids") == session_id.bytes,
                        "token_bytes": len(body["qrst"]) if isinstance(body.get("qrst"), bytes) else None,
                        "key_bytes": len(body["qrsk"]) if isinstance(body.get("qrsk"), bytes) else None}
                    for field in ("qrs", "qec", "qv", "qrp", "link-protocol", "qr"):
                        if type(body.get(field)) is int:
                            relay_details[field] = body[field]
                    append_status("relay_responses", relay_details)
                    if len(relay_messages) < 32:
                        relay_messages.append(base64.b64encode(message.payload).decode("ascii"))
                        capture_save(directory / "live-relay-messages.dpapi", {
                            "received_at": time.time(), "responses_bplist": relay_messages})
                    if body.get("qids") == session_id.bytes and isinstance(body.get("qrst"), bytes) and isinstance(body.get("qrsk"), bytes):
                        result["relay_allocated"] = True
                        capture_save(directory / "live-relay-response.dpapi", {
                            "received_at": time.time(), "response_bplist": base64.b64encode(message.payload).decode("ascii")})
                        if relay is None:
                            relay = RelayBinding(body)
                            relay_status = result.setdefault("relay_binding", {})
                            try:
                                raw = await relay.bind(relay_status)
                                capture_save(directory / "live-relay-binding.dpapi", {"received_at": time.time(),
                                    "response_base64": base64.b64encode(raw).decode("ascii")})
                                pending[asyncio.create_task(relay.receive())] = "relay_udp"
                                if observe_transport:
                                    await relay.start_control()
                                    relay_status["connected_command_sent"] = True
                            except Exception as error:
                                relay_status["error_type"] = type(error).__name__
                if (command not in (233, 234, 235, 236)
                        or body.get("t") != peer.identity.push_token
                        or not protocol.sender_matches_relationship(body.get("sP", ""), (peer.handle,))
                        or not protocol.sender_matches_relationship(body.get("tP", ""), (own_handle,))):
                    continue
                candidate = {"command": command, "topic": topic,
                    "encryption": body.get("E") if body.get("E") in ("pair", "pair-ec") else "unknown"}
                append_status("selected_peer_messages", candidate)
                if body.get("E") != "pair-ec":
                    continue
                with compatible_validator(ids, protocol, result):
                    plain = protocol.decrypt_pair_ec(body["P"], receiver_identity=registered["identity"],
                                                     sender_identity=peer.identity)
                decoded = protocol._load_plist(protocol._maybe_gunzip(plain, "Session message"), "Session message")
                if decoded.get("s") != str(session_id).upper() or decoded.get("v") != 5:
                    continue
                known = {"v", "s", "p", "t", "c", "b", "i", "pcd", "de", "sd", "mi", "sqr", "re", "cc", "e", "declinereason"}
                details = {"command": command, "sender_authenticated": True, "session_id_matches": True,
                           "seconds_after_invitation": round(time.monotonic() - started, 1),
                           "known_fields": sorted(known.intersection(decoded)), "other_field_count": len(set(decoded)-known)}
                for field in ("e", "declinereason"):
                    if type(decoded.get(field)) is int:
                        details[field] = decoded[field]
                for field in ("b", "c"):
                    if isinstance(decoded.get(field), bytes):
                        details[field + "_bytes"] = len(decoded[field])
                append_status("peer_responses", details)
                capture_save(directory / "live-peer-response.dpapi", {"received_at": time.time(),
                    "command": command, "response_bplist": base64.b64encode(plistlib.dumps(decoded, fmt=plistlib.FMT_BINARY)).decode("ascii")})
                if command == 233:
                    result["invitation_accepted"] = True
                elif command in (234, 235):
                    result.update(success=False, phase="peer_ended_session", peer_ended_session=True)
                    return
            if result.get("relay_allocated") and result.get("invitation_accepted"):
                result.update(success=True, phase="live_streaming" if result.get("native_live_ready") else "session_accepted")
                if not observe_transport:
                    return
        if result.get("native_live_ready"):
            result.update(success=True, phase="live_window_finished")
        elif result.get("invitation_accepted"):
            result.update(success=True, phase="session_accepted_transport_incomplete")
        else:
            result.update(success=False, phase="session_setup_incomplete")
    finally:
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        await shutdown_channels(relay, utun.channels, result)
        if sent:
            try:
                await asyncio.wait_for(signal(235, cancellation(session_id, participant_id)), 5)
                result["test_session_cancelled"] = True
            except Exception:
                result["test_session_cancel_failed"] = True
        if relay is not None:
            relay.close()


async def probe(directory, database, result, *, mode="directory", duration=60, capture=True,
                on_observation=None, on_tick=None, trace=None, quiet_after=300):
    if type(quiet_after) not in (int, float) or not 60 <= quiet_after <= 1800:
        raise ValueError("Invalid native Live quiet interval")
    pause = auth_backoff(directory)
    if pause:
        result.update(pause)
        return
    selection = load(directory / "selected-person.dpapi")
    with store.connect(database) as db:
        store.subject(db, selection["alias"], require_active=True)
    trace = trace or AuthTrace()
    state, provider = restore(directory)
    client = FriendsClient(state, provider, trace, native_context=True)
    relationship_task = None
    try:
        result["phase"] = "relationship"
        key = load(directory / "people-key.dpapi")
        private_key = validate_saved_key(key, selection, dsid=client.login["dsid"], device_id=client.device_id)
        previous_key = None
        previous_private_key = None
        if (directory / "previous-people-key.dpapi").exists():
            previous_key = load(directory / "previous-people-key.dpapi")
            previous_private_key = validate_saved_key(previous_key, selection, dsid=client.login["dsid"], device_id=client.device_id)
        response = await client.request()
        relationship = selected_relationship(selection, client.login["dsid"], following(response))
        result["relationship_current"] = True
        if not 1 <= len(relationship.accepted_handles) <= 8:
            raise ValueError("Invalid selected handle count")
        config = json.loads((directory / "push-helper-config.json").read_text())
        if config["onitrack_commit"] != "04dd25312643d8c9aa93c883a343488a4b682635":
            raise ValueError("Unexpected protocol implementation")
        if config["onitrack_path"] not in sys.path:
            sys.path.insert(0, config["onitrack_path"])
        from onitrack import ids, key_acquisition as protocol
        install_verified_transport(ids, trace)
        registered, apns = load(directory / "ids.dpapi"), load(directory / "apns.dpapi")
        if not registered.get("registered") or any(x.get("device_id") != client.device_id for x in (registered, apns)):
            raise ValueError("Registered device mismatch")
        certificate, apns_private_key, token = protocol._load_apns_material(apns)
        own_handle = protocol._registered_self_handle(registered)
        directory_client = protocol.IDSDirectoryClient(registered, user_agent=USER_AGENT)
        await asyncio.to_thread(ids._bag, "id-query")
        result["phase"] = "selected_directory"
        async with verified_connection(certificate, apns_private_key, token, stats=result.setdefault("transport", {})) as connection:
            await protocol._set_apns_active(connection)
            async with AsyncExitStack() as stack:
                streams = {topic: await stack.enter_async_context(connection.notification_stream(topic))
                           for topic in (protocol.IDS_PARENT_TOPIC, TOPIC, RELAY_TOPIC,
                                         "com.apple.private.alloy.fmf")}
                rows = []
                peers = []
                for accepted_handle in relationship.accepted_handles:
                    handle = protocol._ids_directory_uri(accepted_handle)
                    if not protocol.sender_matches_relationship(handle, relationship.accepted_handles):
                        raise ValueError("Handle is outside selection")
                    reply = await directory_client._query_directory(connection, base_token=token,
                        topic=TOPIC, sender=handle, target=own_handle)
                    if reply.get("status") != 0:
                        raise ValueError("Directory rejected selected handle")
                    identities = reply.get("results", {}).get(handle, {}).get("identities", [])
                    if not isinstance(identities, list) or len(identities) > 32:
                        raise ValueError("Invalid directory identities")
                    for entry in identities:
                        if not isinstance(entry, dict):
                            raise ValueError("Invalid directory identity")
                        verified = protocol.select_directory_identity(reply, sender=handle, sender_token=entry.get("push-token"))
                        peers.append(SelectedPeer(handle, verified))
                        rows.append({"handle": handle,
                            "entry_bplist": base64.b64encode(plistlib.dumps(entry, fmt=plistlib.FMT_BINARY)).decode("ascii")})
                        caps = entry.get("client-data", {})
                        result.setdefault("device_capabilities", []).append({
                            "identity_signature_verified": True,
                            "push_token_bytes": len(verified.push_token),
                            "capabilities": {k: bool(caps.get(k)) for k in CAPABILITIES}})
                if load(directory / "selected-person.dpapi") != selection:
                    raise ValueError("Selection changed during directory lookup")
                save_atomic(directory / "live-directory.dpapi", {"account_dsid": client.login["dsid"],
                    "device_id": client.device_id, "fm_id": relationship.fm_id,
                    "received_at": time.time(), "topic": TOPIC, "rows": rows})
                result.update(success=True, selected_device_count=len(rows), phase="directory_verified")
                if mode in ("session", "transport"):
                    result["success"] = False
                    if len(peers) != 1:
                        raise ValueError("A unique selected Live device is required")
                    with store.connect(database) as db:
                        store.subject(db, selection["alias"], require_active=True)
                    last_relationship = time.monotonic()
                    async def tick():
                        nonlocal relationship_task, last_relationship, relationship
                        from .key_listener import selection_ready
                        if not selection_ready(directory, database, selection):
                            raise PermissionError("Selected participant is paused or changed")
                        if relationship_task is not None and relationship_task.done():
                            relationship = selected_relationship(selection, client.login["dsid"], following(relationship_task.result()))
                            relationship_task = None
                            last_relationship = time.monotonic()
                            result["relationship_checked_unix"] = int(time.time())
                        if relationship_task is None and time.monotonic() - last_relationship >= 300:
                            relationship_task = asyncio.create_task(asyncio.wait_for(client.request(), 30))
                        if on_tick is not None:
                            on_tick(result)

                    def decode_payload(payload, received_at):
                        decoded = decode_live(payload, key["advertised_id"], private_key, relationship.fm_id, received_at=received_at)
                        if decoded[0] == 0 and not decoded[2]["authenticated_reports"] and previous_key is not None:
                            decoded = decode_live(payload, previous_key["advertised_id"], previous_private_key,
                                relationship.fm_id, received_at=received_at)
                        return decoded

                    async def accept_key(body, topic, connection):
                        nonlocal key, private_key, previous_key, previous_private_key
                        from .key_probe import save_delivery
                        if (topic not in protocol.KEY_DELIVERY_TOPICS or
                                not protocol.sender_matches_relationship(body.get("sP", ""), relationship.accepted_handles) or
                                not protocol.sender_matches_relationship(body.get("tP", ""), (own_handle,))):
                            return
                        try:
                            with compatible_validator(ids, protocol, result):
                                delivery = await asyncio.wait_for(protocol.verify_key_delivery(body,
                                    relationship=relationship, topic=topic, connection=connection, base_token=token,
                                    directory=directory_client, ids_state=registered), 30)
                        except protocol.KeyAcquisitionError:
                            result["rejected_key_messages"] = result.get("rejected_key_messages", 0) + 1
                            return
                        changed = save_delivery(directory, selection, delivery, dsid=client.login["dsid"],
                            device_id=client.device_id, replace_existing=True)
                        if changed:
                            previous_key, previous_private_key = key, private_key
                        key = load(directory / "people-key.dpapi")
                        private_key = validate_saved_key(key, selection, dsid=client.login["dsid"], device_id=client.device_id)
                        result["key_rotations"] = result.get("key_rotations", 0) + int(changed)
                        await directory_client.send_application_ack(connection, base_token=token, topic=topic, delivery=delivery)

                    await session_setup(connection, streams, ids, protocol, registered, token,
                        own_handle, peers[0], directory, result, observe_transport=mode == "transport",
                        duration=duration, capture=capture, decode_payload=decode_payload,
                        on_observation=on_observation, on_tick=tick, on_key=accept_key,
                        quiet_after=quiet_after)
    finally:
        if relationship_task is not None:
            relationship_task.cancel()
            await asyncio.gather(relationship_task, return_exceptions=True)
        await client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--mode", choices=("directory", "session", "transport"), default="directory")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    result = {"stage": "native_live_setup", "success": False,
              "automatic_retry": False, "native_live_ready": False}
    async def bounded():
        async with asyncio.timeout(100):
            await probe(args.state_dir.resolve(), args.db.resolve(), result, mode=args.mode)
    try:
        with collector_lock(args.state_dir / "key-receiver.lock"):
            asyncio.run(bounded())
    except (Exception, KeyboardInterrupt) as error:
        result.update(success=False, error_type=type(error).__name__)
    write_status(args.state_dir / "live-setup-status.json", result)
    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
