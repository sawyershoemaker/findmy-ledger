"""Offline native wire-shape tests; none implies a working Apple Live session."""
import base64
import plistlib
import unittest
from uuid import UUID

from research.live_codec import (CodecError, ControlType, DestinationType,
    MAX_MESSAGE_BYTES, SessionMessage, decode_message, encode_beacon_context,
    encode_message, location_response)


IDENTIFIER = UUID("2F680D3A-D3C7-4C76-B162-821CE9510149")


def binary(value):
    return plistlib.dumps(value, fmt=plistlib.FMT_BINARY)


class NativeSessionCodecTests(unittest.TestCase):
    def envelope(self, **changes):
        return {"T": -1, "V": 1, "I": str(IDENTIFIER).upper(),
                "P": binary([""]), **changes}

    def test_native_control_discriminators_and_uppercase_keys(self):
        for kind in ControlType:
            data = encode_message(SessionMessage(int(kind), IDENTIFIER, ""))
            wire = plistlib.loads(data)
            self.assertEqual(set(wire), {"T", "V", "I", "P"})
            self.assertEqual(wire["T"], int(kind))
            self.assertEqual(wire["V"], 1)
            self.assertEqual(wire["I"], str(IDENTIFIER).upper())
            self.assertEqual(plistlib.loads(wire["P"]), [""])
        self.assertEqual([int(t) for t in ControlType], [-1, -2, -3])

    def test_decode_independently_constructed_envelope(self):
        message = decode_message(binary(self.envelope(T=-2)))
        self.assertEqual(message.type, -2)
        self.assertEqual(message.identifier, IDENTIFIER)
        self.assertEqual(message.payload, "")

    def test_application_payload_preserves_types_without_interpreting_location(self):
        payload = {"synthetic": [12, -3, 1.25, b"bytes", True]}
        message = decode_message(binary(self.envelope(T=42, P=binary([payload]))))
        self.assertEqual(message.payload, payload)
        self.assertEqual(message.type, 42)

    def test_native_destination_discriminator_and_context(self):
        for kind in DestinationType:
            wire = plistlib.loads(encode_beacon_context(kind, "synthetic-device"))
            self.assertEqual(wire, [1, {"type": int(kind), "destination": "synthetic-device"}])

    def test_rejects_bad_versions_types_and_ids(self):
        changes = ({"T": -4}, {"T": True}, {"T": 2**31}, {"T": 1.0},
                   {"V": 2}, {"V": True}, {"I": str(IDENTIFIER).replace("-", "")},
                   {"I": "x" * 36})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(CodecError):
                decode_message(binary(self.envelope(**change)))

    def test_rejects_unwrapped_ambiguous_and_nonempty_control_payloads(self):
        for payload in (binary([]), binary(["", ""]), binary({"value": ""}),
                        binary(["unexpected"]), b"broken"):
            with self.assertRaises(CodecError):
                decode_message(binary(self.envelope(P=payload)))
        with self.assertRaises(CodecError):
            decode_message(binary({**self.envelope(), "type": -1}))

    def test_limits_and_malformed_plists_fail_without_contents(self):
        for data in (b"", b"bplist00garbage", b"x" * (MAX_MESSAGE_BYTES + 1),
                     plistlib.dumps(self.envelope(), fmt=plistlib.FMT_XML)):
            with self.assertRaises(CodecError) as error:
                decode_message(data)
            self.assertNotIn("2F680D3A", str(error.exception))
        with self.assertRaises(CodecError):
            encode_message(SessionMessage(0, IDENTIFIER, b"x" * MAX_MESSAGE_BYTES))

    def test_invalid_outbound_values(self):
        for message in (SessionMessage(-1, IDENTIFIER, "bad"),
                        SessionMessage(0, "invalid", ""),
                        SessionMessage(0, IDENTIFIER, "", 2)):
            with self.assertRaises(CodecError):
                encode_message(message)
        for kind, destination in ((6, "x"), (True, "x"), (1.0, "x"), (0, ""), (0, "a\x00b"),
                                  (0, "x" * 4097)):
            with self.assertRaises(CodecError):
                encode_beacon_context(kind, destination)

    def test_native_location_data_adapts_without_substituting_outer_timestamp(self):
        encrypted = b"synthetic encrypted payload"
        payload = {"id": b"a" * 32, "mode": "live", "keyType": 1,
                   "locationInfo": [{"location": encrypted, "locationTs": 123.5}]}
        message = decode_message(binary(self.envelope(T=0, P=binary([payload]))))
        response = location_response(message)
        row = response["locationPayload"][0]
        self.assertEqual(base64.b64decode(row["id"]), b"a" * 32)
        self.assertEqual(base64.b64decode(row["locationInfo"][0]["location"]), encrypted)
        self.assertEqual(row["locationInfo"][0]["locationTs"], 123.5)
        self.assertNotIn("observed_at", str(response))

    def test_native_location_adapter_rejects_malformed_or_unsupported_payloads(self):
        good = {"id": b"a" * 32, "locationInfo": [{"location": b"cipher", "locationTs": 0.0}]}
        invalid = ({**good, "id": "a" * 32}, {**good, "mode": False},
                   {**good, "keyType": True}, {**good, "extra": 1},
                   {**good, "locationInfo": [{"location": "text", "locationTs": 0.0}]},
                   {**good, "locationInfo": [{"location": b"cipher", "locationTs": float("nan")}]},
                   {**good, "locationInfo": [{"location": b"cipher", "locationTs": 0.0, "fmt": True}]})
        for payload in invalid:
            with self.assertRaises(CodecError):
                location_response(SessionMessage(0, IDENTIFIER, payload))
        for kind in (False, 1, -1):
            with self.assertRaises(CodecError):
                location_response(SessionMessage(kind, IDENTIFIER, good))


if __name__ == "__main__":
    unittest.main()
