"""Exercise real session setup wiring with distinct synthetic push/report keys."""
import asyncio
from contextlib import asynccontextmanager
import json
import plistlib
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from location_ledger import store
try:
    from research.live_probe import probe, shutdown_channels
    import test_live_payload as fixture
except ImportError:
    probe = None


@unittest.skipIf(probe is None, "Optional protocol dependencies")
class LiveWiringTests(unittest.TestCase):
    def test_native_shutdown_reaches_both_channels_with_one_message_identity(self):
        received = []
        channel = SimpleNamespace(encrypt=lambda payload: payload)
        relay = SimpleNamespace(send_data=AsyncMock(side_effect=lambda payload: received.append(plistlib.loads(payload))))
        status = {}
        asyncio.run(shutdown_channels(relay, {"stream": channel, "stream-0": channel}, status))
        self.assertTrue(status["application_shutdown_sent"])
        self.assertEqual(len(received), 2)
        self.assertEqual(received[0], received[1])
        self.assertEqual(received[0]["T"], -3)
        self.assertEqual(plistlib.loads(received[0]["P"]), [""])

    def test_lost_relay_during_shutdown_does_not_skip_transport_cleanup(self):
        relay = SimpleNamespace(send_data=AsyncMock(side_effect=OSError("synthetic disconnect")))
        status = {}
        asyncio.run(shutdown_channels(relay, {"stream": SimpleNamespace(encrypt=lambda payload: payload)}, status))
        self.assertEqual(status, {"application_shutdown_failed": True})

    def test_apns_private_key_cannot_replace_report_decryption_key(self):
        data = fixture.LivePayloadTests()
        data.setUp()
        selection = {"alias": "fixture", "account_dsid": "account",
            "relationship": {"fm_id": "fixture"}}
        saved = {"selected-person.dpapi": selection, "people-key.dpapi": {"advertised_id": data.advertised},
            "ids.dpapi": {"registered": True, "device_id": "device"}, "apns.dpapi": {"device_id": "device"}}
        entry = {"push-token": b"p"*32, "client-data": {}}
        directory = SimpleNamespace(_query_directory=AsyncMock(return_value={"status": 0,
            "results": {"mailto:selected@example.invalid": {"identities": [entry]}}}))
        protocol = SimpleNamespace(_load_apns_material=lambda _: (b"certificate", b"unrelated APNs TLS key", b"t"*32),
            _registered_self_handle=lambda _: "mailto:viewer@example.invalid", IDSDirectoryClient=lambda *a, **k: directory,
            IDS_PARENT_TOPIC="com.apple.private.ids", _set_apns_active=AsyncMock(),
            _ids_directory_uri=lambda h: "mailto:"+h,
            sender_matches_relationship=lambda sender, handles: sender.removeprefix("mailto:") in handles,
            select_directory_identity=lambda *a, **k: SimpleNamespace(push_token=b"p"*32))
        client = SimpleNamespace(login={"dsid": "account"}, device_id="device", close=AsyncMock(),
            request=AsyncMock(return_value={"following": [{"id": "fixture", "invitationAcceptedHandles": ["selected@example.invalid"]}]}))
        @asynccontextmanager
        async def stream(*args):
            yield object()
        @asynccontextmanager
        async def connection(certificate, private, token, **options):
            self.assertEqual(private, b"unrelated APNs TLS key")
            yield SimpleNamespace(notification_stream=stream)
        async def session(*args, **options):
            kind, observations, status = options["decode_payload"](data.payload([data.report(data.now)]), data.now)
            self.assertEqual(kind, 0)
            self.assertEqual(status["authenticated_reports"], 1)
            self.assertEqual(observations[0]["observed_at"], data.now)
        with tempfile.TemporaryDirectory() as tmp:
            root, database = Path(tmp), Path(tmp)/"history.sqlite"
            store.initialize(database)
            with store.connect(database, write=True) as db:
                store.register(db, "fixture")
            (root/"push-helper-config.json").write_text(json.dumps({"onitrack_commit": "04dd25312643d8c9aa93c883a343488a4b682635", "onitrack_path": tmp}))
            fake_package = SimpleNamespace(ids=SimpleNamespace(_bag=lambda _: None), key_acquisition=protocol)
            try:
                with patch.dict(sys.modules, {"onitrack": fake_package}), \
                        patch("research.live_probe.auth_backoff", return_value=None), \
                        patch("research.live_probe.load", side_effect=lambda p: saved[p.name]), \
                        patch("research.live_probe.restore", return_value=({}, object())), \
                        patch("research.live_probe.FriendsClient", return_value=client), \
                        patch("research.live_probe.validate_saved_key", return_value=data.key), \
                        patch("research.live_probe.install_verified_transport"), \
                        patch("research.live_probe.save_atomic"), \
                        patch("research.live_probe.verified_connection", connection), \
                        patch("research.live_probe.session_setup", side_effect=session):
                    asyncio.run(probe(root, database, {}, mode="transport", capture=False))
            finally:
                if tmp in sys.path:
                    sys.path.remove(tmp)
        client.close.assert_awaited_once()
