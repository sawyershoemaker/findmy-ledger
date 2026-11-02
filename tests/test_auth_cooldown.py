import asyncio
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from research import auth_cooldown
from research.auth_diagnostics import AuthTrace


class CooldownTests(unittest.TestCase):
    def test_pause_is_persistent_and_reading_does_not_extend_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            auth_cooldown.record(path, {"http_status": 429}, now=100)
            first = auth_cooldown.active(path, now=200)
            second = auth_cooldown.active(path, now=300)
            self.assertEqual(first["retry_not_before_utc"], second["retry_not_before_utc"])
            self.assertEqual(first["seconds_remaining"] - second["seconds_remaining"], 100)
            self.assertIsNone(auth_cooldown.active(path, now=2800))

    def test_longer_server_delay_is_honored_and_never_shortened(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            first = auth_cooldown.record(path, {"http_status": 429, "retry_after_seconds": 7200}, now=100)
            second = auth_cooldown.record(path, {"http_status": 429}, now=200)
            self.assertEqual(first["not_before_unix"], second["not_before_unix"])
            self.assertEqual(auth_cooldown.active(path, now=100)["seconds_remaining"], 7200)

    def test_other_failures_do_not_create_a_cooldown(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_cooldown.record(Path(tmp), {"http_status": 503}, now=100)
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_cooldown_blocks_before_input_or_provider_creation(self):
        from research.auth_probe import provision
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            auth_cooldown.record(path, {"http_status": 429})
            with patch("research.auth_probe.check_version"), patch("builtins.input") as prompt, \
                 patch("research.auth_probe.local_provider") as provider, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(asyncio.run(provision(path, AuthTrace())), 2)
            prompt.assert_not_called()
            provider.assert_not_called()
