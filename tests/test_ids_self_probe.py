import unittest
from types import SimpleNamespace
try:
    from research.ids_self_probe import self_envelope
except ImportError:
    self_envelope = None


@unittest.skipIf(self_envelope is None, "Install auth and push-research extras")
class SelfLoopScopeTests(unittest.TestCase):
    def test_single_destination_must_be_current_receiver_token(self):
        own = b"synthetic-own-token"
        directory = SimpleNamespace(push_token=own, session_token=b"synthetic-session")
        body = self_envelope(handle="mailto:self@example.invalid", base_token=own, directory=directory,
                             payload=b"synthetic-encrypted", challenge_id=b"u" * 16)
        self.assertEqual(len(body["dtl"]), 1)
        self.assertEqual(body["dtl"][0]["t"], own)
        self.assertEqual(body["dtl"][0]["tP"], body["sP"])
        self.assertFalse(body["dtl"][0]["D"])
        directory.push_token = b"another-device"
        with self.assertRaises(ValueError):
            self_envelope(handle="mailto:self@example.invalid", base_token=own, directory=directory,
                          payload=b"synthetic", challenge_id=b"u" * 16)

    def test_missing_challenge_identifier_is_rejected(self):
        directory = SimpleNamespace(push_token=b"self", session_token=b"synthetic")
        for value in (b"", b"a" * 15, "u" * 16):
            with self.assertRaises(ValueError):
                self_envelope(handle="mailto:self@example.invalid", base_token=b"self", directory=directory,
                              payload=b"synthetic", challenge_id=value)
