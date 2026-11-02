import hashlib
import importlib.util
import unittest

HAS_CRYPTO = importlib.util.find_spec("cryptography") is not None
if HAS_CRYPTO:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from research.report_codec import decode_private_key, decrypt_report


@unittest.skipUnless(HAS_CRYPTO, "Install the optional protocol dependencies")
class ReportCodecTests(unittest.TestCase):
    def setUp(self):
        self.receiver = ec.generate_private_key(ec.SECP224R1())
        self.public = self.receiver.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.blob = self.public + self.receiver.private_numbers().private_value.to_bytes(28, "big")
        sender = ec.generate_private_key(ec.SECP224R1())
        point = sender.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        shared = sender.exchange(ec.ECDH(), self.receiver.public_key())
        # Independent expression of the first X9.63/SHA-256 block.
        material = hashlib.sha256(shared + b"\x00\x00\x00\x01" + point).digest()
        self.plaintext = b'{"synthetic":true,"latitude":40.0,"longitude":-75.0}'
        self.payload = point + AESGCM(material[:16]).encrypt(material[16:], self.plaintext, None)

    def test_synthetic_envelope(self):
        key = decode_private_key(self.blob)
        self.assertEqual(decrypt_report(self.payload, key), self.plaintext)

    def test_mismatched_point_and_scalar(self):
        with self.assertRaises(ValueError):
            decode_private_key(self.public + (1234).to_bytes(28, "big"))

    def test_corrupted_ciphertext_is_rejected(self):
        changed = self.payload[:-1] + bytes([self.payload[-1] ^ 1])
        with self.assertRaises(InvalidTag):
            decrypt_report(changed, self.receiver)

    def test_other_share_key_cannot_decrypt(self):
        with self.assertRaises(InvalidTag):
            decrypt_report(self.payload, ec.generate_private_key(ec.SECP224R1()))

    def test_wrong_curve_and_short_payload(self):
        with self.assertRaises(ValueError):
            decrypt_report(self.payload, ec.generate_private_key(ec.SECP256R1()))
        with self.assertRaises(ValueError):
            decrypt_report(b"\x04short", self.receiver)


if __name__ == "__main__":
    unittest.main()
