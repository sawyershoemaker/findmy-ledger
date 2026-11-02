"""Bounded read-only Find My CloudKit discovery, with no keychain recovery/login.

Run only in the isolated cloudkit environment. Source provenance and the exact
upstream revision are checked before loading the account. No records are saved.
"""
import argparse
import asyncio
import json
import logging
import subprocess
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

from . import auth_cooldown, searchparty_backoff
from .auth_diagnostics import AuthTrace
from .windows_secrets import load, save_atomic

FORK_COMMIT = "8ecfae6cb34b29caf0bd8176ee73155ca81415a8"
PEOPLE_CONTAINER = "com.apple.findmy.container"
PEOPLE_BUNDLE = "com.apple.findmy.findmylocateagent"
KEYCHAIN_CONTAINER = "com.apple.security.keychain"
KNOWN_ZONES = frozenset({"_defaultZone", "SharedSecrets", "SecureLocations", "SecureLocationKeys", "FriendSharedSecrets",
                         "Friends", "FindMy", "FindMyZone", "CloudStorage", "BeaconStore"})
KNOWN_RECORD_TYPES = frozenset({"FriendSharedSecrets", "FriendSharedSecretsRecord", "SharedSecret", "SharedSecrets"})
KNOWN_FIELDS = frozenset({"friendIdentifier", "friendId", "fmId", "identifier", "sharedSecret", "sharedSecrets",
    "key", "keyData", "recordData", "data", "payload", "version", "schemaVersion", "rootKey", "rootKeys",
    "isShared", "isOwner", "primaryKey", "secondaryKey", "uuid", "UUID", "encryptedData"})


def record_metadata(changes):
    """Only fixed schema labels and counts may leave a record-inspection process."""
    result = []
    for change in changes:
        if not change.HasField("record"):
            continue
        record = change.record
        result.append({"known_type": record.type.name if record.type.name in KNOWN_RECORD_TYPES else None,
            "type_length": len(record.type.name), "protection_present": record.HasField("protection_info"),
            "fields": [{"known_name": f.identifier.name if f.identifier.name in KNOWN_FIELDS else None,
                        "name_length": len(f.identifier.name), "value_type": f.value.type,
                        "encrypted": f.value.is_encrypted, "byte_length": len(f.value.bytes_value)}
                       for f in record.record_field]})
    return result


def checked_cloudkit_url(url, *, container=PEOPLE_CONTAINER):
    if container not in {PEOPLE_CONTAINER, KEYCHAIN_CONTAINER}:
        raise ValueError("Unsupported research container")
    target = urlsplit(url)
    if (target.scheme != "https" or target.hostname != "gateway.icloud.com" or target.port not in (None, 443)
            or target.username or target.password or target.fragment):
        raise ValueError("CloudKit destination is outside the probe scope")
    if target.path == "/setup/setup/ck/v1/ckAppInit":
        if parse_qs(target.query, strict_parsing=True) != {"container": [container]}:
            raise ValueError("CloudKit container is outside the probe scope")
    elif (target.query or target.path not in {
            "/ckdatabase/api/client/zone/retrieve", "/ckdatabase/api/client/record/sync"}):
        raise ValueError("CloudKit operation is outside the read-only probe scope")
    return url


def verify_runtime():
    import findmy
    from findmy.cloudkit import client
    source = Path(findmy.__file__).resolve().parent.parent
    result = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
        capture_output=True, text=True, timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode or result.stdout.strip() != FORK_COMMIT:
        raise ValueError("Unexpected CloudKit research dependency revision")
    return client.AsyncCloudKitClient


def local_provider(directory):
    from .mac_provider import MacProvider

    class CloudKitMacProvider(MacProvider):
        # The fork added a read-only `identity` property for its own dataclass.
        # Keep our existing encrypted machine dictionary and header worker intact.
        @property
        def identity(self):
            return self._ledger_identity

        @identity.setter
        def identity(self, value):
            self._ledger_identity = value

    return CloudKitMacProvider(directory)


class ScopedTransport:
    def __init__(self, directory, stats, *, container=PEOPLE_CONTAINER):
        from findmy.util.http import HttpSession
        self.directory, self.stats = directory, stats
        self.container = container
        self.original = HttpSession()
        self.session = None

    def validate_destination(self, url):
        checked_cloudkit_url(url, container=self.container)

    async def post(self, url, **kwargs):
        from aiohttp import BasicAuth, ClientSession, ClientTimeout, TCPConnector
        from findmy.util.http import HttpResponse
        self.validate_destination(url)
        if searchparty_backoff.active(self.directory):
            raise RuntimeError("Gateway backoff is active")
        if self.session is None:
            self.session = ClientSession(connector=TCPConnector(force_close=True), timeout=ClientTimeout(total=30))
        auth = kwargs.pop("auth", None)
        if isinstance(auth, tuple):
            auth = BasicAuth(*auth)
        async with self.session.post(url, auth=auth, ssl=self.original._ssl, allow_redirects=False, **kwargs) as reply:
            trace = AuthTrace()
            trace.http_response(reply.status, reply.headers.get("Retry-After"))
            details = {"http_status": reply.status}
            if trace.retry_after_seconds is not None:
                details["retry_after_seconds"] = trace.retry_after_seconds
            backoff = searchparty_backoff.record(self.directory, details)
            if backoff:
                details["retry_not_before_utc"] = backoff["retry_not_before_utc"]
            self.stats["last_response"] = details
            self.stats["http_requests"] = self.stats.get("http_requests", 0) + 1
            raw = await searchparty_backoff.read_limited(reply.content, 4 * 1024 * 1024)
            self.stats["response_bytes"] = len(raw)
            return HttpResponse(reply.status, raw, dict(reply.headers))

    async def close(self):
        if self.session is not None:
            await self.session.close()
        await self.original.close()


async def probe(directory, stats, *, shared_secrets=False):
    from .saved_session import validate_session
    client_type = verify_runtime()
    cooldown = auth_cooldown.active(directory) or searchparty_backoff.active(directory)
    if cooldown:
        stats.update(cooldown)
        return
    provider = local_provider(directory)
    client = None
    try:
        state = load(directory / "apple-session.dpapi")
        validate_session(state, provider.identity)
        login = state["login"]["data"]
        selected = load(directory / "selected-person.dpapi")
        if selected.get("account_dsid") != login["dsid"]:
            raise ValueError("Selected participant does not match this account")
        tokens = login["mobileme_data"]["tokens"]
        stats["cloudkit_token_available"] = bool(tokens.get("cloudKitToken"))
        if not tokens.get("cloudKitToken"):
            return

        async def anisette_headers():
            return await provider.get_headers(provider.account_ids["uid"], provider.account_ids["devid"])

        account = SimpleNamespace(serial=provider.identity["serial"], device_uuid=provider.account_ids["devid"],
            client_info=provider.client, timeout=30, dsid=login["dsid"], service_tokens=tokens,
            get_anisette_headers=anisette_headers)
        class ExistingMachineClient(client_type):
            @property
            def _device_hardware_id(self):
                # Provisioning IDs may use Apple's 25-character form. CloudKit's
                # hardware ID is the same real emulated host UUID used by NAC.
                return UUID(provider.identity["host_uuid"]).hex.upper()

        client = ExistingMachineClient(account, container=PEOPLE_CONTAINER, bundle=PEOPLE_BUNDLE, device_name="FindMy Ledger")
        await client._http.close()
        client._http = ScopedTransport(directory, stats)
        stats["phase"] = "open_people_container"
        info = await client.open_container()
        stats["container_opened"] = True
        stats["phase"] = "list_people_zones"
        zones = await client.zone_retrieve()
        stats["zone_count"] = len(zones)
        # Serialized metadata remains local and encrypted, for subsequent scoped
        # queries. No record payload, service token, or response body is retained.
        import base64
        save_atomic(directory / "people-cloudkit-metadata.dpapi", {
            "account_dsid": login["dsid"], "device_id": provider.account_ids["devid"],
            "container": PEOPLE_CONTAINER, "zones": [base64.b64encode(z.SerializeToString()).decode("ascii") for z in zones]})
        if shared_secrets:
            if not any(z.target_zone.zone_identifier.value.name == "SharedSecrets" for z in zones):
                raise ValueError("Expected SharedSecrets zone is absent")
            stats["phase"] = "shared_secrets_metadata"
            # One small page, no automatic pagination, record persistence or decrypt.
            page = await client.record_sync("SharedSecrets", max_changes=100)
            stats["change_count"] = len(page.changes)
            stats["sync_complete"] = page.complete
            stats["record_metadata"] = record_metadata(page.changes)
        stats["success"] = True
    finally:
        if client is not None:
            await client.close()
        await provider.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--doctor", action="store_true")
    parser.add_argument("--shared-secrets", action="store_true", help="Inspect one bounded page of encrypted record metadata")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    result = {"stage": "people_cloudkit_discovery", "success": False, "automatic_retry": False,
              "account_login_attempted": False, "keychain_recovery_attempted": False,
              "live_collection_ready": False}
    try:
        if args.doctor:
            verify_runtime()
            result.update({"success": True, "stage": "cloudkit_dependency_preflight"})
        else:
            asyncio.run(probe(args.state_dir.resolve(), result, shared_secrets=args.shared_secrets))
    except (Exception, KeyboardInterrupt) as error:
        result["error_type"] = type(error).__name__
    if not args.doctor:
        (args.state_dir / "people-cloudkit-status.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
