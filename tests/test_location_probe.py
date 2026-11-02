import asyncio
import base64
import hashlib
import json
import plistlib
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from location_ledger import store
from research.auth_diagnostics import AuthTrace
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from research.location_probe import APPLE_EPOCH, LocationReportError, decoded_observation, newest_observation, probe
except ImportError:
    probe = None

NOW = 1793217600
FM_ID = "synthetic-selected-person"
ADVERTISED = base64.b64encode(b"a" * 32).decode()


@unittest.skipIf(probe is None, "Install auth and push-research extras")
class LocationProbeTests(unittest.TestCase):
    def setUp(self):
        self.key = ec.generate_private_key(ec.SECP224R1())
        self.public = self.key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.blob = self.public + self.key.private_numbers().private_value.to_bytes(28, "big")
        self.fix = {"findMyId": FM_ID, "latitude": 40.0, "longitude": -75.0,
                    "horizontalAccuracy": 12.5, "timestamp": NOW - 30 - APPLE_EPOCH}

    def encrypted(self, data, *, outer_timestamp=0, plist=False):
        sender = ec.generate_private_key(ec.SECP224R1())
        point = sender.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        shared = sender.exchange(ec.ECDH(), self.key.public_key())
        material = hashlib.sha256(shared + b"\0\0\0\1" + point).digest()
        plain = plistlib.dumps(data, fmt=plistlib.FMT_BINARY) if plist else json.dumps(data).encode()
        sealed = point + AESGCM(material[:16]).encrypt(material[16:], plain, None)
        return {"fmt": 0, "location": base64.b64encode(sealed).decode(), "locationTs": outer_timestamp}

    def response(self, *infos):
        return {"statusCode": "200", "locationPayload": [{"id": ADVERTISED, "locationInfo": list(infos)}]}

    def decode(self, response):
        return newest_observation(response, ADVERTISED, self.key, FM_ID, received_at=NOW)

    def test_selects_newest_authenticated_timestamp_and_ignores_other_shares(self):
        older = self.encrypted({**self.fix, "timestamp": NOW - 300 - APPLE_EPOCH}, outer_timestamp=NOW + 10000)
        response = self.response(self.encrypted(self.fix), older)
        response["locationPayload"].insert(0, {"id": "different-share", "locationInfo": [{"location": "not-a-report"}]})
        fix, status = self.decode(response)
        self.assertEqual(fix["observed_at"], NOW - 30)
        self.assertEqual(status["matching_reports"], 2)
        self.assertEqual(status["source_age_seconds"], 30)
        self.assertNotIn("latitude", json.dumps(status))
        self.assertNotIn(FM_ID, json.dumps(status))

    def test_binary_plist_date_is_utc_and_keeps_native_accuracy(self):
        dt = datetime.fromtimestamp(NOW - 30, timezone.utc).replace(tzinfo=None)
        fix, _ = self.decode(self.response(self.encrypted({**self.fix, "timestamp": dt}, plist=True)))
        self.assertEqual(fix["observed_at"], NOW - 30)
        self.assertEqual(fix["accuracy_m"], 12.5)

    def test_missing_accuracy_or_wrong_participant_cannot_become_history(self):
        for change in ({"horizontalAccuracy": None}, {"horizontalAccuracy": -1}, {"findMyId": "different-share"},
                       {"latitude": True}, {"longitude": float("nan")}, {"timestamp": "unknown-time"}):
            with self.subTest(change=change), self.assertRaises(LocationReportError):
                decoded_observation(json.dumps({**self.fix, **change}).encode(), FM_ID)

    def test_stale_future_and_wrong_epoch_are_not_fresh_fixes(self):
        for stamp, reason in ((NOW - 901 - APPLE_EPOCH, "source_report_stale"),
                              (NOW + 301 - APPLE_EPOCH, "source_timestamp_in_future"),
                              (NOW, "source_timestamp_in_future")):
            fix, status = self.decode(self.response(self.encrypted({**self.fix, "timestamp": stamp})))
            self.assertIsNone(fix)
            self.assertEqual(status["reason"], reason)

    def test_delayed_history_keeps_original_time_and_still_rejects_future_or_ancient_reports(self):
        for age in (1800, 86400, 86401, -301):
            response = self.response(self.encrypted({**self.fix, "timestamp": NOW - age - APPLE_EPOCH}))
            fix, status = newest_observation(response, ADVERTISED, self.key, FM_ID, received_at=NOW, accept_delayed=True)
            if age in (1800, 86400):
                self.assertEqual(fix["observed_at"], NOW - age)
                self.assertFalse(status["report_is_fresh"])
                self.assertEqual(status["source_age_seconds"], age)
            else:
                self.assertIsNone(fix)

    def test_corruption_does_not_fall_back_to_an_older_fix(self):
        bad = self.encrypted(self.fix)
        raw = base64.b64decode(bad["location"])
        bad["location"] = base64.b64encode(raw[:-1] + bytes([raw[-1] ^ 1])).decode()
        with self.assertRaises(LocationReportError):
            self.decode(self.response(bad, self.encrypted({**self.fix, "timestamp": NOW - 300 - APPLE_EPOCH})))

    def test_satellite_and_empty_responses_are_not_coordinates(self):
        for response in (self.response(), self.response({"fmt": 1, "location": "some-satellite-data"})):
            fix, status = self.decode(response)
            self.assertIsNone(fix)
            self.assertEqual(status["matching_reports"], 0)

    def test_missing_key_stops_before_credentials_or_network(self):
        with tempfile.TemporaryDirectory() as tmp, patch("research.location_probe.restore") as restore:
            status = {}
            asyncio.run(probe(Path(tmp), AuthTrace(), status))
        restore.assert_not_called()
        self.assertFalse(status["network_request_attempted"])
        self.assertEqual(status["reason"], "verified_people_key_required")

    def test_verified_fixture_ingests_once_and_pause_blocks_network(self):
        selection = {"account_dsid": "123456", "alias": "participant",
                     "relationship": {"fm_id": FM_ID}}
        saved = {"selected-person.dpapi": selection, "people-key.dpapi": {
                    "account_dsid": "123456", "device_id": "synthetic-device", "fm_id": FM_ID,
                    "sender_authenticated": True, "private_key_blob": base64.b64encode(self.blob).decode(),
                    "advertised_id": ADVERTISED},
                 "apns.dpapi": {"device_id": "synthetic-device", "courier_token": "ab" * 32}}
        client = SimpleNamespace(login={"dsid": "123456"}, device_id="synthetic-device", close=AsyncMock(),
            request=AsyncMock(return_value={"following": [{"id": FM_ID, "invitationAcceptedHandles": ["selected@example.invalid"]}]}))
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "people-key.dpapi").touch()
            database = directory / "ledger.sqlite"
            with patch("research.location_probe.restore", return_value=({}, object())), \
                 patch("research.location_probe.FriendsClient", return_value=client), \
                 patch("research.location_probe.load", side_effect=lambda p: saved[p.name]), \
                 patch("research.location_probe.save_atomic") as preview, \
                 patch("research.location_probe.searchparty", new=AsyncMock(return_value=self.response(self.encrypted(self.fix)))) as fetch, \
                 patch("research.location_probe.time.time", return_value=NOW):
                first, second = {}, {}
                asyncio.run(probe(directory, AuthTrace(), first, database=database, capture_encrypted=True))
                asyncio.run(probe(directory, AuthTrace(), second, database=database))
                self.assertTrue(first["new_observation"])
                self.assertFalse(second["new_observation"])
                self.assertNotIn("latitude", json.dumps(first))
                self.assertNotIn(FM_ID, json.dumps(first))
                self.assertEqual(preview.call_count, 3)
                self.assertTrue(first["encrypted_response_cached"])
                self.assertNotIn("latitude", json.dumps(preview.call_args_list[0].args[1]))
                fetch.return_value = self.response(self.encrypted({**self.fix, "timestamp": NOW - 1800 - APPLE_EPOCH}))
                delayed, repeated = {}, {}
                asyncio.run(probe(directory, AuthTrace(), delayed, database=database, accept_delayed=True))
                asyncio.run(probe(directory, AuthTrace(), repeated, database=database, accept_delayed=True))
                self.assertTrue(delayed["new_observation"])
                self.assertFalse(delayed["fresh_report_received"])
                self.assertTrue(delayed["delayed_report_received"])
                self.assertFalse(repeated["new_observation"])
                self.assertEqual(preview.call_count, 3)
                with store.connect(database, write=True) as db:
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM samples").fetchone()[0], 2)
                    self.assertEqual(db.execute("SELECT min(observed_at) FROM samples").fetchone()[0], NOW - 1800)
                    db.execute("UPDATE subjects SET active=0")
                client.request.reset_mock()
                fetch.reset_mock()
                with self.assertRaises(ValueError):
                    asyncio.run(probe(directory, AuthTrace(), {}, database=database))
                client.request.assert_not_awaited()
                fetch.assert_not_awaited()
