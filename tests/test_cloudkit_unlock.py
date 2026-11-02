import asyncio
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from research.cloudkit_probe import KEYCHAIN_CONTAINER, PEOPLE_CONTAINER
from research.cloudkit_unlock import check_recovery_url, consume_pet, matching_pcs_records

HAS_AUTH = importlib.util.find_spec("findmy") is not None
try:
    HAS_CLOUDKIT = HAS_AUTH and importlib.util.find_spec("findmy.cloudkit") is not None
except ModuleNotFoundError:
    HAS_CLOUDKIT = False


class RecoveryScopeTests(unittest.TestCase):
    def test_recovery_rejects_writes_redirect_targets_and_other_hosts(self):
        for suffix in ("get_records", "srp_init", "recover"):
            url = "https://p01-escrowproxy.icloud.com:443/escrowproxy/api/" + suffix
            self.assertEqual(check_recovery_url(url, container=KEYCHAIN_CONTAINER, escrow_host="p01-escrowproxy.icloud.com"), url)
        for suffix in ("enroll", "delete", "get_records?redirect=evil", "recover/extra"):
            with self.assertRaises(ValueError):
                check_recovery_url("https://p01-escrowproxy.icloud.com/escrowproxy/api/" + suffix,
                                   container=KEYCHAIN_CONTAINER, escrow_host="p01-escrowproxy.icloud.com")
        for url in ("https://p02-escrowproxy.icloud.com/escrowproxy/api/recover",
                    "https://p01-escrowproxy.icloud.com.evil.invalid/escrowproxy/api/recover",
                    "https://user@p01-escrowproxy.icloud.com/escrowproxy/api/recover",
                    "http://p01-escrowproxy.icloud.com/escrowproxy/api/recover"):
            with self.assertRaises(ValueError):
                check_recovery_url(url, container=KEYCHAIN_CONTAINER, escrow_host="p01-escrowproxy.icloud.com")
        code = "https://gateway.icloud.com/ckcode/api/client/code/invoke"
        self.assertEqual(check_recovery_url(code, container=KEYCHAIN_CONTAINER), code)
        with self.assertRaises(ValueError):
            check_recovery_url(code, container=PEOPLE_CONTAINER)

    def test_consumed_pet_expires_and_is_bound_to_account_machine(self):
        state = {"login": {"data": {"dsid": "123"}}, "protocol_bootstrap": {"adsid": "SYNTHETIC_ADSID"}}
        identity = {"device_id": "SYNTHETIC_DEVICE"}
        token = {"account_dsid": "123", "device_id": "SYNTHETIC_DEVICE", "adsid": "SYNTHETIC_ADSID",
                 "created_at": 1000, "pet": "SYNTHETIC_PET"}
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for change, ok in [({}, True), ({"created_at": 700}, False), ({"created_at": 1100}, False),
                               ({"account_dsid": "456"}, False), ({"device_id": "OTHER"}, False),
                               ({"adsid": "OTHER"}, False), ({"pet": ""}, False)]:
                path = directory / "keychain-pet.dpapi"
                path.write_bytes(b"synthetic ciphertext")
                value = {**token, **change}
                with patch("research.cloudkit_unlock.load", return_value=value):
                    if ok:
                        self.assertEqual(consume_pet(directory, state, identity, now=1001), value)
                    else:
                        with self.assertRaises(ValueError):
                            consume_pet(directory, state, identity, now=1001)
                self.assertFalse(path.exists())

    @unittest.skipUnless(HAS_CLOUDKIT, "Isolated CloudKit dependency")
    def test_only_public_reference_matched_item_is_selected(self):
        from findmy.cloudkit.proto import cloudkit_pb2 as ck
        from findmy.cloudkit.records import CloudKitRecord
        records = []
        for kind, public in [("item", b"A" * 32), ("item", b"B" * 32), ("currentitem", b"A" * 32)]:
            proto = ck.Record(type=ck.NameWrapper(name=kind))
            f = proto.record_field.add()
            f.identifier.name = "pcspublickey"
            f.value.bytes_value = public
            records.append(CloudKitRecord.from_proto(proto, "Manatee"))
        self.assertEqual(matching_pcs_records(records, {b"A" * 32}), [records[0]])

    @unittest.skipUnless(HAS_AUTH, "Optional authentication dependency")
    def test_stop_before_service_exchange_leaves_pet_unspent(self):
        from findmy import LoginState
        from research.keychain_pet import keep_unspent_pet
        account = SimpleNamespace(login_state=LoginState.AUTHENTICATED, _login_state_data={"idms_pet": "SYNTHETIC_PET"})
        self.assertEqual(asyncio.run(keep_unspent_pet(account)), LoginState.AUTHENTICATED)
        account._login_state_data = {}
        with self.assertRaises(ValueError):
            asyncio.run(keep_unspent_pet(account))

    @unittest.skipUnless(HAS_CLOUDKIT, "Isolated CloudKit dependency")
    def test_metadata_does_not_include_private_field_names_or_values(self):
        from findmy.cloudkit.proto import cloudkit_pb2 as ck
        from research.cloudkit_probe import record_metadata
        change = ck.RecordChange()
        change.record.type.name = "FriendSharedSecretsRecord"
        f = change.record.record_field.add()
        f.identifier.name = "private-person@example.invalid"
        f.value.string_value = "SYNTHETIC_SECRET"
        output = json.dumps(record_metadata([change]))
        self.assertNotIn("private-person", output)
        self.assertNotIn("SYNTHETIC_SECRET", output)
