"""Distinct synthetic sender and receiver keys; no real account data."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "work/upstream/onitrack"))
    from onitrack import ids, key_acquisition as protocol
except ImportError:
    protocol = None

from research.ngm_compat import compatible_validator


@unittest.skipIf(protocol is None, "Pinned Onitrack checkout and crypto dependencies")
class NGMCompatibilityTests(unittest.TestCase):
    def setUp(self):
        sender, device, prekey, ephemeral = [ids._generate_compact_p256() for _ in range(4)]
        self.identity = {name: key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
            for name, key in (("device_private_key_pem", device), ("pre_private_key_pem", prekey))}
        self.sender = SimpleNamespace(device_public_key=sender.public_key())
        sx, dx, px, ex = [ids._compact_public_key(key) for key in (sender, device, prekey, ephemeral)]
        secret = ephemeral.exchange(ec.ECDH(), prekey.public_key())
        material = HKDF(algorithm=hashes.SHA256(), length=48, salt=b"LastPawn-MessageKeys", info=b"").derive(secret)
        self.plain = b"synthetic authenticated application message"
        inner = ids._proto_bytes(1, self.plain)
        padding = (-len(inner)) % 16
        encryptor = Cipher(algorithms.AES(material[:32]), modes.CTR(material[32:])).encryptor()
        encrypted = encryptor.update(inner + b"\0" * padding + padding.to_bytes(4, "little")) + encryptor.finalize()
        r, s = utils.decode_dss_signature(sender.sign(secret + px + ex + dx + encrypted, ec.ECDSA(hashes.SHA256())))
        self.fields = {1: encrypted, 2: ex, 3: r.to_bytes(32, "big") + s.to_bytes(32, "big"),
                       99: sx[:2] + dx[:2] + px[:2] + b"\x0d"}

    def wire(self, changes=None):
        return b"".join(ids._proto_bytes(field, value) for field, value in {**self.fields, **(changes or {})}.items())

    def decode(self, wire):
        return protocol.decrypt_pair_ec(wire, receiver_identity=self.identity, sender_identity=self.sender)

    def test_version_is_separate_from_identity_and_full_signature_still_verifies(self):
        with self.assertRaises(protocol.KeyAcquisitionError):
            self.decode(self.wire())
        stats, original = {}, protocol.decrypt_pair_ec
        with compatible_validator(ids, protocol, stats):
            self.assertEqual(self.decode(self.wire()), self.plain)
        self.assertIs(protocol.decrypt_pair_ec, original)
        self.assertEqual(stats["ngm_validation"]["version_byte"], 13)
        self.assertTrue(stats["ngm_validation"]["message_signature_verified"])

    def test_changed_identity_or_signature_is_rejected(self):
        bad_validator = bytes([self.fields[99][0] ^ 1]) + self.fields[99][1:]
        bad_signature = bytes([self.fields[3][0] ^ 1]) + self.fields[3][1:]
        for changes in ({99: bad_validator}, {3: bad_signature}):
            stats = {}
            with compatible_validator(ids, protocol, stats), self.assertRaises(protocol.KeyAcquisitionError):
                self.decode(self.wire(changes))
            self.assertFalse(stats["ngm_validation"]["message_signature_verified"])

    def test_malformed_and_duplicated_validator_are_rejected(self):
        for wire in (self.wire({99: self.fields[99][:6]}), self.wire({99: self.fields[99] + b"\0"}),
                     self.wire() + ids._proto_bytes(99, self.fields[99])):
            with compatible_validator(ids, protocol, {}), self.assertRaises(protocol.KeyAcquisitionError):
                self.decode(wire)
