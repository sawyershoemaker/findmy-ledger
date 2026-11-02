"""One local escrow unlock, restricted to the PCS item protecting Find My SharedSecrets."""
import argparse
import asyncio
import base64
import getpass
import json
import logging
import re
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit
from uuid import UUID

from . import auth_cooldown, searchparty_backoff
from .cloudkit_probe import (KEYCHAIN_CONTAINER, PEOPLE_CONTAINER, PEOPLE_BUNDLE, ScopedTransport,
                            checked_cloudkit_url, local_provider, verify_runtime)
from .windows_secrets import load, save_atomic

READ_FUNCTIONS = frozenset({"fetchViableBottles", "fetchChanges", "fetchRecoverableTLKShares"})
ESCROW_COMMANDS = frozenset({"get_records", "srp_init", "recover"})


def check_recovery_url(url, *, container, escrow_host=None):
    target = urlsplit(url)
    if (target.scheme != "https" or target.port not in (None, 443) or target.username or target.password
            or target.fragment):
        raise ValueError("Invalid recovery destination")
    if escrow_host:
        if (target.hostname != escrow_host or not re.fullmatch(r"p[0-9]{1,3}-escrowproxy\.icloud\.com", escrow_host)
                or target.query or target.path not in {"/escrowproxy/api/" + c for c in ESCROW_COMMANDS}):
            raise ValueError("Escrow operation is outside recovery scope")
    elif (container == KEYCHAIN_CONTAINER and target.hostname == "gateway.icloud.com" and not target.query
            and target.path in {"/ckcode/api/client/code/invoke", "/ckcoderouter/api/client/code/invoke"}):
        pass
    else:
        checked_cloudkit_url(url, container=container)
    return url


class RecoveryTransport(ScopedTransport):
    def __init__(self, directory, stats, *, container, escrow_host=None):
        super().__init__(directory, stats, container=container)
        self.escrow_host = escrow_host

    def validate_destination(self, url):
        check_recovery_url(url, container=self.container, escrow_host=self.escrow_host)

    async def post(self, url, **kwargs):
        if self.stats.get("http_requests", 0) >= 60:
            raise ValueError("Bounded recovery request limit reached")
        if self.escrow_host:
            import plistlib
            payload = plistlib.loads(kwargs["data"])
            payload["userActionLabel"] = "FindMy Ledger selected participant sharing-key recovery"
            kwargs["data"] = plistlib.dumps(payload)
        return await super().post(url, **kwargs)


def consume_pet(directory, state, identity, *, now=None):
    path = directory / "keychain-pet.dpapi"
    try:
        token = load(path)
    finally:
        path.unlink(missing_ok=True)
    age = (time.time() if now is None else now) - token.get("created_at", 0)
    if (not -5 <= age < 240 or token.get("account_dsid") != state["login"]["data"]["dsid"]
            or token.get("device_id") != identity["device_id"]
            or token.get("adsid") != state.get("protocol_bootstrap", {}).get("adsid")
            or not isinstance(token.get("pet"), str) or not token["pet"]):
        raise ValueError("Escrow credential is stale or belongs to another identity")
    return token


def matching_pcs_records(records, references):
    from findmy.cloudkit.records import plain_value
    found = []
    for record in records:
        if record.record_type != "item":
            continue
        entry = record.fields.get("pcspublickey")
        public = plain_value(entry.value) if entry is not None else None
        if isinstance(public, bytes) and (public in references or (len(public) == 33 and public[1:] in references)):
            found.append(record)
    return found


def context(directory):
    from .saved_session import validate_session
    from findmy.reports.anisette import DeviceIdentity
    provider = local_provider(directory)
    state = load(directory / "apple-session.dpapi")
    validate_session(state, provider.identity)
    selected = load(directory / "selected-person.dpapi")
    if selected.get("account_dsid") != state["login"]["data"]["dsid"]:
        raise ValueError("Selected participant does not match this account")
    groups = re.findall(r"<([^>]+)>", provider.client)
    os_parts = groups[1].split(";")
    if os_parts[1:] != ["13.1", "22C65"]:
        raise ValueError("Escrow headers need a verified identity for this OS")
    identity = DeviceIdentity(model=groups[0], os_name=os_parts[0], os_version=os_parts[1], os_build=os_parts[2],
                              cfnetwork="1404.0.5", darwin="22.2.0")
    async def anisette_headers():
        return await provider.get_headers(provider.account_ids["uid"], provider.account_ids["devid"])
    async def no_automatic_authentication():
        raise ValueError("Escrow credential expired; no automatic authentication or recovery retry")
    login = state["login"]["data"]
    account = SimpleNamespace(serial=provider.identity["serial"], device_uuid=provider.account_ids["devid"],
        client_info=provider.client, timeout=30, dsid=login["dsid"], adsid=state["protocol_bootstrap"]["adsid"],
        account_name=state["account"]["username"], service_tokens=login["mobileme_data"]["tokens"], identity=identity,
        get_anisette_headers=anisette_headers, request_pet=no_automatic_authentication)
    return state, selected, provider, account


async def make_client(directory, stats, provider, account, *, container, bundle):
    client_type = verify_runtime()
    class ReadClient(client_type):
        @property
        def _device_hardware_id(self):
            return UUID(provider.identity["host_uuid"]).hex.upper()

        async def function_invoke(self, service, name, parameters):
            if container != KEYCHAIN_CONTAINER or service != "Cuttlefish" or name not in READ_FUNCTIONS:
                raise ValueError("Only the three read-only trust queries are permitted")
            return await super().function_invoke(service, name, parameters)

        async def record_sync(self, zone_name, **kwargs):
            if zone_name not in ("SharedSecrets", "Manatee"):
                raise ValueError("Zone is outside sharing-key recovery scope")
            return await super().record_sync(zone_name, **kwargs)

    client = ReadClient(account, container=container, bundle=bundle, device_name="FindMy Ledger")
    await client._http.close()
    client._http = RecoveryTransport(directory, stats, container=container)
    return client


async def unlock(directory, stats, *, capabilities=False):
    from findmy.cloudkit.pcs import ShareProtection, public_key_forms
    from findmy.cloudkit.records import records_from_changes
    from findmy.keychain.cuttlefish import fetch_viable_bottles
    from findmy.keychain.escrow import AsyncEscrowProxy, escrow_host
    from findmy.keychain.items import decrypt_item, payload_of
    from findmy.keychain.session import AsyncKeychainSession
    from findmy.keychain.servicekey import service_keys_from_der
    from findmy.keychain.shares import fetch_recoverable_shares, unwrap_share
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    if auth_cooldown.active(directory) or searchparty_backoff.active(directory):
        stats.update(reason="server_backoff_active")
        return
    if not capabilities and not sys.stdin.isatty():
        raise ValueError("Recovery requires an interactive local terminal")
    state, selected, provider, account = context(directory)
    clients = []
    session = proxy = None
    passcode = token = peer = None
    try:
        for container, bundle in [(PEOPLE_CONTAINER, PEOPLE_BUNDLE), (KEYCHAIN_CONTAINER, "com.apple.security.cuttlefish"),
                                  (KEYCHAIN_CONTAINER, "com.apple.securityd")]:
            clients.append(await make_client(directory, stats, provider, account, container=container, bundle=bundle))
        people, cuttlefish, securityd = clients
        stats["phase"] = "read_recovery_capabilities"
        if capabilities:
            bottles = await fetch_viable_bottles(cuttlefish)
            stats.update(success=True, viable_backup_count=len(bottles.valid), partial_backup_count=bottles.partial_count)
            return
        token = consume_pet(directory, state, provider.identity)
        info = await people.open_container()
        if not info.partition:
            raise ValueError("No verified escrow partition")
        host = escrow_host(info.partition)
        proxy = AsyncEscrowProxy(account, host, token["pet"])
        await proxy._http.close()
        proxy._http = RecoveryTransport(directory, stats, container=KEYCHAIN_CONTAINER, escrow_host=urlsplit(host).hostname)
        session = AsyncKeychainSession(account, people, cuttlefish, securityd, proxy)
        session._pet_obtained_at = time.monotonic() - (time.time() - token["created_at"])
        options = await session.recovery_options()
        stats["recoverable_backup_count"] = len(options.recoverable)
        if not options.recoverable:
            raise ValueError("No recoverable device backup")
        print("Device backups below are shown only in this terminal.")
        for i, record in enumerate(options.recoverable, 1):
            name = record.device_name or "Unnamed device"
            model = record.device_model or "Unknown model"
            stamp = record.escrowed_at.isoformat() if record.escrowed_at else "Unknown date"
            print(f"{i}: {name} | {model} | backup {stamp}")
        choice = int(input("Choose a device whose screen-lock passcode you know: ")) - 1
        if not 0 <= choice < len(options.recoverable):
            raise ValueError("Invalid device selection")
        print("One attempt only. Use the screen-lock passcode for that device, not your Apple password.")
        passcode = getpass.getpass("Device screen-lock passcode (hidden): ")
        if not passcode:
            raise ValueError("Passcode is required")
        stats["phase"] = "recover_selected_device_backup"
        stats["recovery_attempts"] = 1
        peer = await session.recover(options.recoverable[choice], passcode)
        passcode = None
        if not peer.bottle.sponsor_known or not peer.bottle.sponsor_verified:
            raise ValueError("Recovered identity signature is not verified")
        stats["recovered_identity_verified"] = True
        stats["phase"] = "unwrap_manatee_share"
        directory_peers = await session.peer_directory()
        entries = await fetch_recoverable_shares(cuttlefish, peer.peer_id)
        shares = [unwrap_share(e, peer.encryption_key(), directory_peers, expected_receiver=peer.peer_id)
                  for e in entries if e.view == "Manatee"]
        keyrings = [s.view_keys for s in shares if s.sender_known and s.sender_verified and s.view_keys]
        if not keyrings:
            raise ValueError("No authenticated Manatee key share")
        stats["manatee_share_verified"] = True
        stats["phase"] = "read_matching_pcs_item"
        zones = await people.zone_retrieve()
        zone = next(z.target_zone for z in zones if z.target_zone.zone_identifier.value.name == "SharedSecrets")
        references = {k.public_key for k in ShareProtection.from_der(zone.protection_info.protection_info).keys}
        page = await securityd.record_sync("Manatee", max_changes=200)
        if not page.complete:
            raise ValueError("Bounded Manatee page is incomplete")
        candidates = matching_pcs_records(records_from_changes(page.changes, "Manatee"), references)
        if len(candidates) != 1:
            raise ValueError("Expected exactly one matching PCS key item")
        # Only this public-key-matched item is decrypted; other keychain items stay sealed.
        item = None
        for ring in keyrings:
            try:
                item = decrypt_item(candidates[0], ring)
                break
            except Exception:
                continue
        if item is None:
            raise ValueError("Matching PCS item did not authenticate")
        keys = service_keys_from_der(payload_of(item))
        if not (public_key_forms(keys.encryption_key.public_key()) & references):
            raise ValueError("PCS item's private and public keys disagree")
        save_atomic(directory / "people-pcs-key.dpapi", {"account_dsid": account.dsid,
            "device_id": provider.account_ids["devid"], "fm_id": selected["relationship"]["fm_id"],
            "container": PEOPLE_CONTAINER, "zone": "SharedSecrets", "saved_at": time.time(),
            "keychain_item_authenticated": True, "private_keys": [base64.b64encode(k.private_bytes(
                Encoding.DER, PrivateFormat.PKCS8, NoEncryption())).decode("ascii") for k in keys.for_pcs()]})
        stats.update(success=True, keychain_items_decrypted=1, matching_pcs_key_saved=True)
    finally:
        passcode = token = peer = None
        if session:
            await session.close()
        else:
            if proxy:
                await proxy.close()
            for client in clients:
                await client.close()
        await provider.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--doctor", action="store_true")
    parser.add_argument("--capabilities", action="store_true")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    stats = {"stage": "findmy_cloud_key_unlock", "success": False, "automatic_retry": False,
             "account_login_attempted": False, "recovery_attempts": 0, "keychain_items_decrypted": 0,
             "live_collection_ready": False}
    if not args.doctor and not args.capabilities:
        stats["reason"] = "nearby_finding_key_recovery_disabled_map_key_relevance_unverified"
        print(json.dumps(stats, indent=2))
        return 2
    try:
        verify_runtime()
        if args.doctor:
            state, selected, provider, account = context(args.state_dir.resolve())
            asyncio.run(provider.close())
            stats.update(success=True, stage="cloud_key_unlock_preflight", account_requests=0)
        else:
            asyncio.run(unlock(args.state_dir.resolve(), stats, capabilities=args.capabilities))
    except (Exception, KeyboardInterrupt) as error:
        stats["error_type"] = type(error).__name__
    if not args.doctor:
        (args.state_dir / "cloud-key-unlock-status.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    print(json.dumps(stats, indent=2))
    return 0 if stats["success"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
