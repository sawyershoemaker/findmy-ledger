"""STUN integrity checks include the independent RFC 5769 section 2.1 vector."""
import struct
import unittest

from research.live_relay import (ALLOCATE_BIND, COOKIE, INTEGRITY, RelayBinding,
    RelayProtocolError, decode_stun, encode_stun)


class RelayWireTests(unittest.TestCase):
    def test_rfc5769_integrity_vector_without_optional_fingerprint(self):
        # https://www.rfc-editor.org/rfc/rfc5769.html#section-2.1
        # Native IDS puts MESSAGE-INTEGRITY last. Remove RFC's FINGERPRINT and
        # set the header length to end at MI (the RFC's HMAC input length).
        packet = bytes.fromhex(
            "00010050 2112a442 b7e7a701bc34d686fa87dfae "
            "80220010 5354554e207465737420636c69656e74 "
            "00240004 6e0001ff 80290008 932ff9b151263b36 "
            "00060009 6576746a3a68367659202020 "
            "00080014 9aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2")
        result = decode_stun(packet, b"VOkJxbRl1RmTxUk/WvJxBt")
        self.assertEqual(result.type, 1)
        self.assertEqual(result.attributes[6], b"evtj:h6vY")
        changed = packet[:30] + bytes([packet[30] ^ 1]) + packet[31:]
        with self.assertRaises(RelayProtocolError):
            decode_stun(changed, b"VOkJxbRl1RmTxUk/WvJxBt")

    def test_native_allocation_header_padding_and_integrity(self):
        transaction, key = b"t" * 12, b"k" * 20
        packet = encode_stun(ALLOCATE_BIND, transaction,
                             [(0xFFF2, b"synthetic-token"), (25, b"\x11\0\0\0")], key)
        kind, size, cookie, received_id = struct.unpack_from("!HHI12s", packet)
        self.assertEqual((kind, size, cookie, received_id), (0xEE0, len(packet)-20, COOKIE, transaction))
        self.assertEqual(decode_stun(packet, key, transaction=transaction).attributes[25], b"\x11\0\0\0")
        for bad_key, expected_id in ((b"wrong", transaction), (key, b"x" * 12)):
            with self.assertRaises(RelayProtocolError):
                decode_stun(packet, bad_key, transaction=expected_id)

    def test_malformed_lengths_duplicates_and_unsigned_packets_are_rejected(self):
        packet = encode_stun(ALLOCATE_BIND, b"t"*12, [(0xFFF2, b"token")], b"k"*20)
        for bad in (b"", packet[:-1], packet + b"\0\0\0\0", packet[:2]+b"\x00\x04"+packet[4:],
                    packet[:8] + b"x" * 12 + packet[20:]):
            with self.assertRaises(RelayProtocolError):
                decode_stun(bad, b"k"*20)
        for attrs in ([(8, b"x"*20)], [(1, b"x"), (1, b"y")]):
            with self.assertRaises(RelayProtocolError):
                encode_stun(ALLOCATE_BIND, b"t"*12, attrs, b"key")

    def test_relay_endpoint_must_come_with_valid_credentials_and_public_address(self):
        base = {"qrip": bytes([17, 1, 2, 3]), "qrp": 3491, "qrsk": b"k" * 20, "qrst": b"synthetic-token"}
        for changes in ({"qrip": b"\x7f\0\0\1"}, {"qrip": "example.invalid"}, {"qrp": True},
                        {"qrsk": b"short"}, {"qrst": b""}):
            with self.assertRaises(RelayProtocolError):
                RelayBinding({**base, **changes})
        relay = RelayBinding(base)
        self.assertIsNone(relay.socket)
        relay.close()

    def test_diagnostics_never_treat_channel_data_as_authenticated(self):
        relay = RelayBinding({"qrip": bytes([17, 1, 2, 3]), "qrp": 3491,
                              "qrsk": b"k" * 20, "qrst": b"synthetic-token"})
        relay.channel = 0x4001
        packet = struct.pack("!HH", 0x4001, 6) + b"secret"
        summary = relay.packet_summary(packet)
        self.assertEqual(summary, {"kind": "channel", "bytes": 10, "authenticated": False,
                                  "channel_matches": True, "declared_payload_bytes": 6})
        self.assertNotIn("secret", repr(summary))
        stun = encode_stun(0xFE0, b"t"*12, [(12, b"\x40\x01\0\0")], relay.key)
        self.assertTrue(relay.packet_summary(stun)["authenticated"])
        with self.assertRaises(RelayProtocolError):
            relay.packet_summary(stun[:-1] + bytes([stun[-1] ^ 1]))


if __name__ == "__main__":
    unittest.main()
