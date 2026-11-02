import hashlib
import hmac
import struct
import unittest

from research.live_control import (connected_attributes, decode_control,
    decode_indication, encode_control, encode_indication)
from research.live_relay import RelayProtocolError


class ControlTests(unittest.TestCase):
    def test_independent_unpadded_native_wire_layout(self):
        key = bytes(range(16))
        # Native writeIDSGLAttrU16 writes exactly six bytes, without STUN padding.
        prefix = bytes.fromhex("00010024") + b"\0" * 16 + bytes.fromhex("001200020002000c00020001")
        packet = prefix + bytes.fromhex("00090014") + hmac.digest(key, prefix, hashlib.sha1)
        result = decode_control(packet, key)
        self.assertEqual(result.command, 1)
        self.assertEqual(result.attributes[18], b"\0\x02")
        self.assertEqual(encode_control(1, [(18, b"\0\x02"), (12, b"\0\x01")], key), packet)
        for changed in (packet[:-1], packet+b"\0", packet[:26]+bytes([packet[26]^1])+packet[27:]):
            with self.assertRaises(RelayProtocolError):
                decode_control(changed, key)
        with self.assertRaises(RelayProtocolError):
            decode_control(packet, b"x" * 16)

    def test_indication_channel_and_inner_authentication_both_required(self):
        key = b"k" * 16
        inner = encode_control(1, connected_attributes(b"l" * 16), key)
        outgoing = encode_indication(0x4005, inner)
        incoming = b"\0\x17" + outgoing[2:]
        self.assertEqual(decode_indication(incoming, 0x4005, key).command, 1)
        for packet, channel in ((outgoing, 0x4005), (incoming, 0x4006), (incoming[:-4], 0x4005)):
            with self.assertRaises(RelayProtocolError):
                decode_indication(packet, channel, key)
        with self.assertRaises(RelayProtocolError):
            decode_indication(incoming, 0x4005, b"x" * 16)

    def test_duplicate_and_malformed_attributes_are_rejected_even_if_signed(self):
        key = b"k" * 16
        for attrs in ([(1, b"bad")], [(1, b"\0\x01"), (1, b"\0\x02")], [(9, b"x" * 20)]):
            with self.assertRaises(RelayProtocolError):
                encode_control(1, attrs, key)
        for body in (bytes.fromhex("000100020001000100020002"), bytes.fromhex("00120003010203")):
            prefix = struct.pack("!HH16s", 1, len(body)+24, b"\0"*16) + body
            packet = prefix + bytes.fromhex("00090014") + hmac.digest(key, prefix, hashlib.sha1)
            with self.assertRaises(RelayProtocolError):
                decode_control(packet, key)


if __name__ == "__main__":
    unittest.main()
