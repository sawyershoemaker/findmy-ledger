import struct
import unittest
from uuid import UUID

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from research.live_utun import UTunSession, stream_keys, stream_transform, hello
except ImportError:
    UTunSession = None
from research.live_relay import RelayProtocolError
from research.live_tcp import checksum

SID = UUID("c1405026-fb07-4a35-a97d-6f5d2a603b47")
GUID = b"B2A423DC-E2FB-43B1-BB02-9FDE2F151D9F"


@unittest.skipIf(UTunSession is None, "Optional cryptography dependency unavailable")
class UTunTests(unittest.TestCase):
    def test_hello_supports_enrolled_40_hex_udid_without_changing_auth_identity(self):
        packet = hello("a"*40, str(SID))
        self.assertEqual(packet[0], 1)
        self.assertEqual(packet, hello("a"*40, str(SID)))
        self.assertNotEqual(packet, hello("b"*40, str(SID)))
        self.assertIn(SID.bytes, packet)

    def request(self, name=None):
        account, service = b"fixture", b"com.apple.private.alloy.fmd"
        name = name or str(SID).upper().encode()
        return struct.pack("!BB7HIHH", 6, 17, 1026, 1025, 36, 0, len(account), len(service),
            len(name), 42, 65534, 60) + GUID + account + service + name + bytes(range(60))

    def test_key_derivation_matches_native_cbc_block_chaining(self):
        material = bytes(range(30))
        key, salt = stream_keys(material)
        def block(data):
            enc = Cipher(algorithms.AES(material[:16]), modes.ECB()).encryptor()
            return enc.update(data)+enc.finalize()
        first = block(material[16:]+b"\0\0")
        second = block(bytes(a^b for a,b in zip(first, material[16:]+b"\0\x01")))
        self.assertEqual(key, first+second)
        counter = bytearray(material[16:]+b"\0\0")
        counter[7] ^= 2
        self.assertEqual(salt, block(bytes(counter))[:14])

    def test_channel_reply_is_scoped_idempotent_and_oppositely_keyed(self):
        session = UTunSession(SID, None, None, str(SID))
        request = self.request()
        reply = session._setup_channel(request)
        self.assertEqual(session._setup_channel(request), reply)
        channel = next(iter(session.channels.values()))
        self.assertEqual(struct.unpack_from("!HH", reply, 2), (1025, 1026))
        merged = bytes(a^b for a,b in zip(bytes(range(60)),reply[-60:]))
        expected = merged[30:] if channel.local_guid>GUID else merged[:30]
        self.assertEqual(channel.receive_material, expected)
        with self.assertRaises(RelayProtocolError):
            session._setup_channel(self.request(b"unrelated-session"))
        with self.assertRaises(RelayProtocolError):
            session._setup_channel(request+b"trailing")

    def test_datagram_checksum_replay_and_rollover_do_not_authenticate_application(self):
        session = UTunSession(SID, None, None, str(SID))
        session._setup_channel(self.request())
        channel = next(iter(session.channels.values()))
        payload = b"synthetic application payload"
        udp = struct.pack("!HHHH", 1026, 1025, len(payload)+8, 0)+payload
        digest = checksum(b"\0"*32+struct.pack("!I",len(udp))+b"\0\0\0\x11"+udp)
        plain = b"\0"+udp[:6]+struct.pack("!H", digest)+udp[8:]
        for index in (65534, 65535, 65536):
            # Native begins with last-sequence zero. The high initial sequence
            # belongs to ROC uint32(-1), then wraps into ROC zero.
            wire_index = (index-65536) & ((1<<48)-1)
            packet = b"\xe0\0"+struct.pack("!HI",index&65535,42)+stream_transform(channel.receive_material,42,wire_index,plain)
            decoded_index, decoded = channel.decrypt(packet)
            self.assertEqual((decoded_index,decoded), (index,payload))
            # A checksum-valid transport packet alone cannot consume the replay window.
            self.assertNotIn(index,channel.seen or set())
            channel.mark_authenticated(index)
            with self.assertRaises(RelayProtocolError):
                channel.decrypt(packet)
        tampered = packet[:-1]+bytes([packet[-1]^1])
        with self.assertRaises(RelayProtocolError):
            session.decrypt_datagram(tampered)

    def test_outbound_nonce_monotonic_and_checksum_correct_across_rollover(self):
        session = UTunSession(SID, None, None, str(SID))
        session._setup_channel(self.request())
        channel = next(iter(session.channels.values()))
        channel.local_start = 65535
        for index in (65535, 65536, 65537):
            packet = channel.encrypt(b"synthetic heartbeat")
            sequence, ssrc = struct.unpack_from("!HI", packet, 2)
            self.assertEqual(sequence, index & 65535)
            plain = stream_transform(channel.send_material, ssrc, (index-65536)&((1<<48)-1), packet[8:])
            self.assertEqual(struct.unpack_from("!HH", plain, 1), (1025, 1026))
            self.assertEqual(checksum(b"\0"*32+struct.pack("!I",len(plain)-1)+b"\0\0\0\x11"+plain[1:]), 0)
            self.assertEqual(plain[9:], b"synthetic heartbeat")
        channel.send_index = 1 << 48
        with self.assertRaises(RelayProtocolError):
            channel.encrypt(b"exhausted")

    def test_native_zero_last_sequence_nonce_boundaries(self):
        from research.live_utun import DataChannel
        self.assertEqual(DataChannel.wire_index(32767, 32767), 32767)
        self.assertEqual(DataChannel.wire_index(32768, 32768), (0xffffffff << 16) | 32768)
        self.assertEqual(DataChannel.wire_index(65535, 40000), (1 << 48)-1)
        self.assertEqual(DataChannel.wire_index(65536, 40000), 0)
        self.assertEqual(DataChannel.wire_index(65536, 100), 65536)
