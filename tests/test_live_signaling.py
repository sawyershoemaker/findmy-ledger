"""Synthetic one-to-one session identities; no account or network access."""
from pathlib import Path
import plistlib
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import UUID

from research.live_signaling import (SelectedPeer, allocation_request, cancellation,
    invitation, seal_message, session_envelope)
from research.ngm_compat import compatible_validator

try:
    from cryptography.hazmat.primitives import serialization
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "work/upstream/onitrack"))
    from onitrack import ids, key_acquisition as protocol
except ImportError:
    protocol = None

SID = UUID("0c645bd5-f163-4551-b383-0e0b17f70282")
PID = UUID("f0d81241-c552-40ab-9a0f-620413c615b6")
HANDLE = "mailto:consenting-synthetic@example.invalid"


class SignalingBuilderTests(unittest.TestCase):
    def setUp(self):
        self.peer = SelectedPeer(HANDLE, SimpleNamespace(push_token=b"t" * 32, session_token=b"synthetic-directory"))

    def test_one_to_one_allocation_has_one_recipient_and_native_version(self):
        request = allocation_request(SID, "mailto:viewer@example.invalid", self.peer, request_id=PID)
        self.assertEqual(request["U"], PID.bytes)
        self.assertEqual(request["qids"], SID.bytes)
        self.assertEqual((request["c"], request["qat"], request["qv"], request["qsats"]), (200, 1, 25, 0))
        self.assertEqual(request["qai"], "com.apple.private.alloy.fmd")
        self.assertEqual(len(request["dtl"]), 1)
        self.assertEqual(request["dtl"][0]["t"], b"t" * 32)
        self.assertNotIn("qgid", request)
        self.assertNotIn("P", request["dtl"][0])

    def test_invitation_retains_encryption_integrity_and_correct_context(self):
        body = invitation(SID, PID, self.peer)
        self.assertEqual(body["s"], str(SID).upper())
        self.assertEqual(body["p"], str(PID).upper())
        self.assertEqual(plistlib.loads(body["c"]), [1, {"type": 2, "destination": "token:" + (b"t"*32).hex() + "/" + HANDLE}])
        self.assertFalse(body["de"])
        self.assertTrue(body["mi"])
        self.assertTrue(body["sqr"])
        self.assertEqual(cancellation(SID, PID), {"v": 5, "s": str(SID).upper(), "p": str(PID).upper()})

    def test_session_envelope_targets_exactly_the_selected_identity(self):
        message = session_envelope(232, "mailto:viewer@example.invalid", self.peer, b"synthetic-ciphertext", message_id=SID)
        self.assertEqual(message["U"], SID.bytes)
        self.assertEqual(message["dtl"], [{"tP": HANDLE, "D": False, "t": b"t" * 32,
            "sT": b"synthetic-directory", "P": b"synthetic-ciphertext", "E": "pair-ec"}])
        self.assertNotIn("consenting", repr(self.peer))

    def test_rejects_unsupported_commands_malformed_tokens_and_identifiers(self):
        for command in (True, 242, 200, -1):
            with self.assertRaises(ValueError):
                session_envelope(command, "mailto:viewer@example.invalid", self.peer, b"ciphertext")
        with self.assertRaises(ValueError):
            invitation(str(SID), PID, self.peer)
        self.peer.identity.push_token = b"short"
        with self.assertRaises(ValueError):
            allocation_request(SID, "mailto:viewer@example.invalid", self.peer)


@unittest.skipIf(protocol is None, "Pinned Onitrack checkout and crypto dependencies")
class SignalingEncryptionTests(unittest.TestCase):
    def setUp(self):
        self.sender, self.device, self.prekey = [ids._generate_compact_p256() for _ in range(3)]
        def pem(key):
            return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()).decode()
        self.local = {"device_private_key_pem": pem(self.sender)}
        self.remote = {"device_private_key_pem": pem(self.device), "pre_private_key_pem": pem(self.prekey)}
        self.recipient = SimpleNamespace(device_public_key=self.device.public_key(), prekey_public_key=self.prekey.public_key())
        self.sender_directory = SimpleNamespace(device_public_key=self.sender.public_key())

    def test_distinct_sender_recipient_interoperate_with_independent_decoder(self):
        plain = plistlib.dumps({"s": str(SID).upper(), "synthetic": True}, fmt=plistlib.FMT_BINARY)
        sealed = seal_message(ids, self.local, self.recipient, plain, counter=0)
        diagnostic = {}
        parsed = []
        parser = protocol._parse_protobuf
        def capture(data, label):
            value = parser(data, label)
            parsed.append(value)
            return value
        with compatible_validator(ids, protocol, diagnostic), patch.object(protocol, "_parse_protobuf", side_effect=capture):
            decoded = protocol.decrypt_pair_ec(sealed, receiver_identity=self.remote, sender_identity=self.sender_directory)
        self.assertEqual(decoded, plain)
        self.assertTrue(diagnostic["ngm_validation"]["message_signature_verified"])
        self.assertEqual(parsed[-1][2], [0])

    def test_substituted_sender_and_corrupt_ciphertext_fail_authentication(self):
        sealed = seal_message(ids, self.local, self.recipient, b"synthetic-session", counter=1)
        fields = protocol._parse_protobuf(sealed, "synthetic")
        cipher = protocol._one_bytes(fields, 1, "cipher")
        modified = b"".join(ids._proto_bytes(k, (bytes([cipher[0] ^ 1]) + cipher[1:]) if k == 1
            else protocol._one_bytes(fields, k, "field")) for k in (1, 2, 3, 99))
        wrong_sender = SimpleNamespace(device_public_key=ids._generate_compact_p256().public_key())
        for wire, sender in ((sealed, wrong_sender), (modified, self.sender_directory)):
            with compatible_validator(ids, protocol, {}), self.assertRaises(protocol.KeyAcquisitionError):
                protocol.decrypt_pair_ec(wire, receiver_identity=self.remote, sender_identity=sender)

    def test_replay_counter_is_mandatory_and_uint32_exhaustion_fails_closed(self):
        for counter in (-1, True, 1.0, 0xffffffff, None):
            with self.assertRaises(ValueError):
                seal_message(ids, self.local, self.recipient, b"synthetic", counter=counter)


if __name__ == "__main__":
    unittest.main()
