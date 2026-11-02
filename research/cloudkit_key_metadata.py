"""Identify an encrypted PCS key by its public reference, without decrypting keychain items."""
import argparse
import asyncio
import base64
import json
import logging
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

from . import auth_cooldown, searchparty_backoff
from .cloudkit_probe import KEYCHAIN_CONTAINER, PEOPLE_CONTAINER, ScopedTransport, local_provider, verify_runtime
from .saved_session import validate_session
from .windows_secrets import load


async def probe(directory, stats):
    from findmy.cloudkit.proto import cloudkit_pb2 as ck
    from findmy.cloudkit.pcs import ShareProtection
    from findmy.cloudkit.records import records_from_changes, plain_value
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
        metadata = load(directory / "people-cloudkit-metadata.dpapi")
        if (selected.get("account_dsid") != login["dsid"]
                or metadata.get("account_dsid") != login["dsid"] or metadata.get("container") != PEOPLE_CONTAINER
                or metadata.get("device_id") != provider.account_ids["devid"]):
            raise ValueError("Account, machine or participant binding failed")
        zone = next(z.target_zone for blob in metadata["zones"]
                    if (z := ck.ZoneSummary.FromString(base64.b64decode(blob))).target_zone.zone_identifier.value.name == "SharedSecrets")
        references = {k.public_key for k in ShareProtection.from_der(zone.protection_info.protection_info).keys}
        async def anisette_headers():
            return await provider.get_headers(provider.account_ids["uid"], provider.account_ids["devid"])
        account = SimpleNamespace(serial=provider.identity["serial"], device_uuid=provider.account_ids["devid"],
            client_info=provider.client, timeout=30, dsid=login["dsid"], service_tokens=login["mobileme_data"]["tokens"],
            get_anisette_headers=anisette_headers)
        class ExistingMachineClient(client_type):
            @property
            def _device_hardware_id(self):
                return UUID(provider.identity["host_uuid"]).hex.upper()
        client = ExistingMachineClient(account, container=KEYCHAIN_CONTAINER, bundle="com.apple.securityd", device_name="FindMy Ledger")
        await client._http.close()
        client._http = ScopedTransport(directory, stats, container=KEYCHAIN_CONTAINER)
        stats["phase"] = "open_key_metadata"
        await client.open_container()
        summaries = []
        for view in ("Manatee", "ProtectedCloudStorage"):
            stats["phase"] = "inspect_" + view
            page = await client.record_sync(view, max_changes=200)
            records = list(records_from_changes(page.changes, view))
            counts = {"view": view, "records": len(records), "complete": page.complete, "public_reference_matches": 0,
                      "public_key_fields": 0, "service_ids": {}}
            for record in records:
                field = record.fields.get("pcspublickey")
                public = plain_value(field.value) if field is not None else None
                service = record.fields.get("pcsservice")
                service_id = plain_value(service.value) if service is not None else None
                if isinstance(service_id, int) and 0 <= service_id <= 1000:
                    counts["service_ids"][str(service_id)] = counts["service_ids"].get(str(service_id), 0) + 1
                if isinstance(public, bytes):
                    counts["public_key_fields"] += 1
                    if public in references or (len(public) == 33 and public[1:] in references):
                        counts["public_reference_matches"] += 1
            summaries.append(counts)
        stats.update(success=True, views=summaries)
    finally:
        if client:
            await client.close()
        await provider.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    stats = {"stage": "pcs_key_metadata", "success": False, "account_login_attempted": False,
             "keychain_items_decrypted": 0, "live_collection_ready": False, "automatic_retry": False}
    try:
        asyncio.run(probe(args.state_dir.resolve(), stats))
    except (Exception, KeyboardInterrupt) as error:
        stats["error_type"] = type(error).__name__
    (args.state_dir / "pcs-key-metadata-status.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    print(json.dumps(stats, indent=2))
    return 0 if stats["success"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
