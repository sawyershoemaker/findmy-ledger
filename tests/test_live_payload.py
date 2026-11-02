import base64
import hashlib
import json
import plistlib
import unittest
from uuid import uuid4

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from research.live_payload import decode, heartbeat
    from research.location_probe import LocationReportError, APPLE_EPOCH
except ImportError:
    decode = None


@unittest.skipIf(decode is None, "Optional protocol dependencies")
class LivePayloadTests(unittest.TestCase):
    def setUp(self):
        self.key = ec.generate_private_key(ec.SECP224R1())
        self.advertised = base64.b64encode(b"x"*32).decode()
        self.now = 1793232000

    def report(self, stamp, **overrides):
        sender = ec.generate_private_key(ec.SECP224R1())
        point = sender.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        secret = sender.exchange(ec.ECDH(), self.key.public_key())
        material = hashlib.sha256(secret+b"\0\0\0\1"+point).digest()
        plain = json.dumps({"findMyId": "fixture", "latitude": 40.0, "longitude": -75.0,
            "horizontalAccuracy": 10, "timestamp": stamp-APPLE_EPOCH, **overrides}).encode()
        return {"fmt": 0, "location": point+AESGCM(material[:16]).encrypt(material[16:], plain, None)}

    def payload(self, reports, **overrides):
        return plistlib.dumps({"T": 0, "V": 1, "I": str(uuid4()), "P": plistlib.dumps([
            {"id": b"other"*6, "locationInfo": [{"location": b"untrusted other participant"}]},
            {"id": b"x"*32, "locationInfo": reports}], fmt=plistlib.FMT_BINARY), **overrides}, fmt=plistlib.FMT_BINARY)

    def decode(self, payload):
        return decode(payload, self.advertised, self.key, "fixture", received_at=self.now)

    def test_authenticates_all_reports_and_preserves_order_and_delays(self):
        kind, reports, status = self.decode(self.payload([self.report(self.now-1), self.report(self.now-1800), self.report(self.now-1)]))
        self.assertEqual(kind, 0)
        self.assertEqual([p["observed_at"] for p in reports], [self.now-1800, self.now-1])
        self.assertEqual(status, {"authenticated_reports": 3})

    def test_corruption_wrong_inner_participant_and_conflict_fail_closed(self):
        corrupt = self.report(self.now)
        corrupt["location"] = corrupt["location"][:-1]+bytes([corrupt["location"][-1]^1])
        for reports in ([corrupt], [self.report(self.now, findMyId="unselected")],
                [self.report(self.now), self.report(self.now, latitude=41.0)]):
            with self.assertRaises(LocationReportError):
                self.decode(self.payload(reports))

    def test_expired_and_future_reports_are_authenticated_but_not_saved(self):
        _, reports, status = self.decode(self.payload([self.report(self.now-86401), self.report(self.now+301)]))
        self.assertEqual(reports, [])
        self.assertEqual(status["authenticated_reports"], 2)

    def test_heartbeat_is_never_authenticated_location(self):
        for kind in (-1, -2, -3):
            decoded, reports, status = self.decode(heartbeat(kind))
            self.assertEqual(decoded, kind)
            self.assertEqual(reports, [])
            self.assertEqual(status["authenticated_reports"], 0)

    def test_envelope_types_and_unknown_version_fail_closed(self):
        for fields in ({"V": True}, {"V": 2}, {"T": True}, {"T": 9}, {"I": "invalid"}, {"P": b"garbage"}):
            with self.assertRaises(LocationReportError):
                self.decode(self.payload([], **fields))
