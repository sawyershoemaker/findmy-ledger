"""Inspect/refresh this receiver's secure-location capability using saved IDS certificates.

Native findmylocated's secureLocationsKeyUpdate requires supportsSecureLocations.
IDSClientDataGenerator advertises supports-secure-loc-v1 as a plist boolean.
No password, new identity, invitation, or participant message is sent here.
"""
import argparse
import asyncio
import base64
import copy
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sys
import time
from types import SimpleNamespace

from .auth_cooldown import active, record
from .auth_diagnostics import AuthTrace
from .windows_secrets import load, save_atomic, save_new

CAPABILITY = "supports-secure-loc-v1"
REVISION = "04dd25312643d8c9aa93c883a343488a4b682635"


def install_secure_location_capability(ids):
    ids.MULTIPLEX_CLIENT_DATA = {**ids.MULTIPLEX_CLIENT_DATA, CAPABILITY: True}


def receiver_capabilities(directory, handle, token):
    if directory.get("status") != 0:
        raise ValueError("Directory query was not accepted")
    rows = directory.get("results", {}).get(handle, {}).get("identities", [])
    matches = [row for row in rows if isinstance(row, dict) and row.get("push-token") == token]
    if len(matches) != 1:
        raise ValueError("Directory does not uniquely identify this receiver")
    values = matches[0].get("client-data", {})
    result = {}
    for name in (CAPABILITY, "supports-fmd-v2", "supports-incoming-fmd-v1", "supports-findmy-plugin-messages"):
        value = values.get(name)
        result[name] = value if type(value) is bool else value == 1 if type(value) is int else False
    return result


async def inspect(directory, ids, protocol, trace):
    from cryptography.hazmat.primitives import serialization
    from .push_receiver import verified_connection
    registered, apns = load(directory / "ids.dpapi"), load(directory / "apns.dpapi")
    if not registered.get("registered") or registered.get("device_id") != apns.get("device_id"):
        raise ValueError("Saved receiver identities differ")
    certificate, key, token = protocol._load_apns_material(apns)
    handle = protocol._registered_self_handle(registered)
    client = protocol.IDSDirectoryClient(registered, user_agent="[macOS,13.1,22C65,MacBookPro13,2]")
    await asyncio.to_thread(ids._bag, "id-query")
    async with asyncio.timeout(65):
        async with verified_connection(certificate, key, token) as connection:
            await protocol._set_apns_active(connection)
            async with connection.notification_stream(protocol.IDS_PARENT_TOPIC):
                response = await client._query_directory(connection, base_token=token,
                    topic="com.apple.private.alloy.fmd", sender=handle, target=handle)
                identity = protocol.select_directory_identity(response, sender=handle, sender_token=token)
                for field, public in (("device_private_key_pem", identity.device_public_key),
                                      ("pre_private_key_pem", identity.prekey_public_key)):
                    private = serialization.load_pem_private_key(registered["identity"][field].encode(), None)
                    if private.public_key().public_numbers() != public.public_numbers():
                        raise ValueError("Directory keys differ from this receiver")
                return {"directory_matches_local_keys": True,
                        "receiver_capabilities": receiver_capabilities(response, handle, token)}


async def refresh(directory, ids, trace, stats):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from .ids_probe import fresh_validation
    from .saved_session import restore
    state, provider = restore(directory)
    try:
        registered, apns = load(directory / "ids.dpapi"), load(directory / "apns.dpapi")
        device_id = provider.account_ids["devid"]
        if not registered.get("registered") or any(s.get("device_id") != device_id for s in (registered, apns)):
            raise ValueError("Saved account and device bindings differ")
        users = registered.get("users", {})
        if len(users) != 1:
            raise ValueError("Expected exactly one registered account")
        user_id, user = next(iter(users.items()))
        if "mailto:" + state["account"]["username"].lower() not in [h.lower() for h in user["handles"]]:
            raise ValueError("Registered handles do not match the signed-in account")
        cert_der = base64.b64decode(user["auth_cert"], validate=True)
        cert = x509.load_der_x509_certificate(cert_der)
        private = serialization.load_pem_private_key(user["auth_private_key_pem"].encode(), None)
        now = datetime.now(timezone.utc)
        if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
            raise ValueError("Saved IDS authentication certificate expired")
        if cert.public_key().public_numbers() != private.public_key().public_numbers():
            raise ValueError("IDS authentication certificate and key differ")
        profile = registered["device_profile_details"]
        if (profile.get("hardware_version"), profile.get("software_version"), profile.get("software_build_id")) != ("MacBookPro13,2", "13.1", "22C65"):
            raise ValueError("Unverified device profile")
        device = SimpleNamespace(display_name="FindMy Ledger (Windows)", product_type=profile["hardware_version"],
            os_version=profile["software_version"], os_build=profile["software_build_id"], udid=device_id,
            fmf_udid=device_id, serial_number=provider.identity["serial"], software_name="macOS")
        backup = directory / "ids-before-secure-location-capability.dpapi"
        if not backup.exists():
            save_new(backup, registered)
        trace.enter("ids_validation")
        validation = await asyncio.to_thread(fresh_validation, directory, device_id)
        auth = ids._AuthKeyPair(cert_der, private, user["auth_private_key_pem"])
        identity = ids._load_or_create_identity(registered["identity"])
        install_secure_location_capability(ids)
        stats["registration_attempted"] = True
        updated = await asyncio.to_thread(ids._id_register, user_id=user_id, auth=auth,
            handles=list(user["handles"]), identity=identity, push_token=bytes.fromhex(apns["courier_token"]),
            push_cert=ids._load_certificate_der(apns, "certificate_pem"),
            push_key=ids._load_rsa_private_key(apns, "private_key_pem"), device=device,
            validation_data=base64.b64decode(validation["validation_data"], validate=True))
        if set(updated["handles"]) != set(user["handles"]):
            raise ValueError("Registration changed the accepted handle set")
        replacement = copy.deepcopy(registered)
        replacement["users"][user_id]["registration"] = updated
        replacement["secure_location_capability_advertised"] = True
        replacement["capability_refreshed_at"] = time.time()
        save_atomic(directory / "ids.dpapi", replacement)
        stats.update(registration_refreshed=True, identity_keys_changed=False, saved_auth_certificate_reused=True)
    finally:
        await provider.close()


async def probe(directory, trace, stats, *, update=False):
    from .ids_probe import install_verified_transport
    config = json.loads((directory / "push-helper-config.json").read_text())
    if config["onitrack_commit"] != REVISION:
        raise ValueError("Unexpected IDS implementation")
    sys.path.insert(0, config["onitrack_path"])
    from onitrack import ids, key_acquisition as protocol
    install_verified_transport(ids, trace)
    stats.update(await inspect(directory, ids, protocol, trace))
    if update and not stats["receiver_capabilities"][CAPABILITY]:
        await refresh(directory, ids, trace, stats)
        stats.update(await inspect(directory, ids, protocol, trace))
    stats["secure_location_capability_verified"] = stats["receiver_capabilities"][CAPABILITY]
    stats["success"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--refresh", action="store_true")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    trace = AuthTrace()
    stats = {"stage": "ids_secure_location_capability", "success": False, "registration_attempted": False,
             "automatic_retry": False, "password_requested": False, "live_collection_ready": False}
    try:
        cooldown = active(args.state_dir)
        if cooldown:
            stats.update(cooldown)
        else:
            from .collector import collector_lock
            with collector_lock(args.state_dir / "key-receiver.lock"):
                asyncio.run(probe(args.state_dir.resolve(), trace, stats, update=args.refresh))
    except (Exception, KeyboardInterrupt) as error:
        stats.update(trace.failure(error))
        record(args.state_dir, stats)
    (args.state_dir / "ids-capability-status.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    print(json.dumps(stats, indent=2))
    return 0 if stats.get("success") else 2


if __name__ == "__main__":
    raise SystemExit(main())
