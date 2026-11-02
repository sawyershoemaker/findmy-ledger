import unittest

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from research.live_pair import PairIdentity, encrypt_pair, decrypt_pair, public_identity
except ImportError:
    PairIdentity = None
from research.live_relay import RelayProtocolError


@unittest.skipIf(PairIdentity is None, "Optional cryptography dependency unavailable")
class PairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sender = PairIdentity(ec.generate_private_key(ec.SECP256R1()), rsa.generate_private_key(65537, 1280))
        cls.receiver = PairIdentity(ec.generate_private_key(ec.SECP256R1()), rsa.generate_private_key(65537, 1280))
        cls.sender_public = PairIdentity(cls.sender.signing.public_key(), cls.sender.encryption.public_key())
        cls.receiver_public = PairIdentity(cls.receiver.signing.public_key(), cls.receiver.encryption.public_key())

    def test_verified_short_and_split_rsa_aes_envelopes(self):
        for body in (b"", b"synthetic hello", bytes(range(256))*5):
            packet = encrypt_pair(body, self.sender, self.receiver_public)
            self.assertEqual(decrypt_pair(packet, self.receiver, self.sender_public), body)
            with self.assertRaises(InvalidSignature):
                decrypt_pair(packet, self.receiver, self.receiver_public)
            with self.assertRaises(InvalidSignature):
                decrypt_pair(packet[:-1]+bytes([packet[-1]^1]), self.receiver, self.sender_public)

    def test_declared_sizes_and_trailing_bytes_rejected(self):
        packet = encrypt_pair(b"fixture", self.sender, self.receiver_public)
        for bad in (packet[:-1], packet+b"\0", b"\x03"+packet[1:], packet[:1]+b"\0\0"+packet[3:]):
            with self.assertRaises(RelayProtocolError):
                decrypt_pair(bad, self.receiver, self.sender_public)
        for bad in (b"", b"0\x80"+b"x"*200):
            with self.assertRaises(RelayProtocolError):
                public_identity(bad)
