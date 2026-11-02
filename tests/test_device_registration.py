import asyncio
import copy
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from research.auth_diagnostics import AuthTrace
from research.auth_probe import save_refreshed_session
try:
    from research.device_registration import run
except ImportError:
    run = None
from research.io_encoder import encode
from research.windows_secrets import load, save_new


@unittest.skipUnless(os.name == "nt", "DPAPI requires Windows")
@unittest.skipIf(run is None, "Install the auth extra")
class RegistrationTests(unittest.TestCase):
    def session(self):
        return {"ids": {"uid": "synthetic-user", "devid": "synthetic-device"},
                "account": {"password": None}, "login": {"data": {"dsid": "123456"}},
                "protocol_bootstrap": {"idms_pet": "synthetic-old-token"}}

    def test_refresh_keeps_account_and_machine_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "session.dpapi"
            previous = self.session()
            save_new(path, previous)
            refreshed = copy.deepcopy(previous)
            refreshed["protocol_bootstrap"]["idms_pet"] = "synthetic-new-token"
            save_refreshed_session(path, refreshed, previous)
            self.assertEqual(load(path), refreshed)
            self.assertNotIn(b"synthetic-new-token", path.read_bytes())

    def test_failed_refresh_validation_preserves_original_ciphertext(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "session.dpapi"
            previous = self.session()
            save_new(path, previous)
            original = path.read_bytes()
            for field, value in (("dsid", "654321"), ("devid", "other-device"), ("password", "synthetic-password")):
                bad = copy.deepcopy(previous)
                if field == "dsid":
                    bad["login"]["data"][field] = value
                elif field == "devid":
                    bad["ids"][field] = value
                else:
                    bad["account"][field] = value
                with self.assertRaises(ValueError):
                    save_refreshed_session(path, bad, previous)
                self.assertEqual(path.read_bytes(), original)

    def test_registration_consumes_fresh_session_immediately_once(self):
        events = []
        async def login(*args, **kwargs):
            self.assertTrue(kwargs["refresh_existing"])
            events.append("login")
            return 0
        async def register(*args):
            events.append("register")
            raise ValueError("synthetic server rejection")
        with tempfile.TemporaryDirectory() as tmp, patch("research.device_registration.active", return_value=None), \
             patch("research.device_registration.preflight"), \
             patch("research.device_registration.provision", side_effect=login) as sign_in, \
             patch("research.device_registration.register", side_effect=register) as register_device:
            with self.assertRaises(ValueError):
                asyncio.run(run(Path(tmp), AuthTrace()))
            self.assertEqual(events, ["login", "register"])
            sign_in.assert_called_once()
            register_device.assert_called_once()

    def test_completed_registration_never_prompts_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            save_new(path / "ids.dpapi", {"registered": True, "users": {"synthetic": {}}})
            with patch("research.device_registration.active", return_value=None), \
                 patch("research.device_registration.preflight"), \
                 patch("research.device_registration.provision", new_callable=AsyncMock) as sign_in:
                self.assertTrue(asyncio.run(run(path, AuthTrace()))["ids_registered"])
                sign_in.assert_not_called()

    def test_unknown_encoding_binary_is_rejected_before_emulation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "encoder.dll"
            path.write_bytes(b"synthetic-not-an-encoder")
            with self.assertRaises(ValueError):
                encode(path, b"synthetic-hardware")
