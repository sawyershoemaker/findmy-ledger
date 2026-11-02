import os
import tempfile
import unittest
from pathlib import Path

from research.auth_probe import remove_password, summary
from research.windows_secrets import load, save_new, save_atomic, transform


class AuthSnapshotTests(unittest.TestCase):
    def test_password_is_removed_without_mutating_account(self):
        original = {"account": {"password": "test-password"}, "login": {"data": {}}}
        cleaned = remove_password(original)
        self.assertIsNone(cleaned["account"]["password"])
        self.assertEqual(original["account"]["password"], "test-password")

    def test_status_contains_no_identifiers_or_tokens(self):
        state = {"account": {"username": "synthetic@example.invalid"},
                 "login": {"data": {"mobileme_data": {"tokens": {"searchPartyToken": "SECRET"}}}}}
        result = str(summary(state))
        self.assertNotIn("SECRET", result)
        self.assertNotIn("example.invalid", result)
        self.assertFalse(summary(state)["live_collection_ready"])


@unittest.skipUnless(os.name == "nt", "Windows-only DPAPI tests")
class WindowsSecretTests(unittest.TestCase):
    def test_encrypted_round_trip_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "session.dpapi"
            data = {"token": "synthetic-session-secret"}
            save_new(path, data)
            self.assertNotIn(b"synthetic-session-secret", path.read_bytes())
            self.assertEqual(load(path), data)
            with self.assertRaises(FileExistsError):
                save_new(path, {"token": "replacement"})
            self.assertEqual(load(path), data)

    def test_invalid_blob_rejected(self):
        with self.assertRaises(OSError):
            transform(b"not-a-dpapi-blob", decrypt=True)

    def test_mutable_state_replacement_leaves_only_ciphertext(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "machine.dpapi"
            save_atomic(path, {"secret": "synthetic-first-state"})
            save_atomic(path, {"secret": "synthetic-updated-state"})
            self.assertEqual(load(path), {"secret": "synthetic-updated-state"})
            self.assertNotIn(b"synthetic", path.read_bytes())
            self.assertEqual(list(Path(temp).iterdir()), [path])


if __name__ == "__main__":
    unittest.main()
