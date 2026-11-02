import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from research.auth_diagnostics import AuthTrace
from research.searchparty_backoff import SearchPartyError, active, record, read_limited


class SearchPartyBackoffTests(unittest.TestCase):
    def test_explicit_503_override_keeps_record_and_never_bypasses_429(self):
        with tempfile.TemporaryDirectory() as directory:
            record(directory, {"http_status": 503, "retry_after_seconds": 1800}, now=100)
            self.assertIsNone(active(directory, now=120, ignore_503=True))
            self.assertIsNotNone(active(directory, now=120))
            self.assertTrue((Path(directory) / "searchparty-backoff.json").exists())
            record(directory, {"http_status": 429, "retry_after_seconds": 2400}, now=120)
            self.assertIsNotNone(active(directory, now=130, ignore_503=True))

    def test_fragmented_response_is_complete_and_oversized_response_stops(self):
        class Content:
            async def iter_chunked(self, size):
                for chunk in (b'{"sta', b'tusCode":', b'200}'):
                    yield chunk
        self.assertEqual(json.loads(asyncio.run(read_limited(Content(), 100))), {"statusCode": 200})
        with self.assertRaises(SearchPartyError):
            asyncio.run(read_limited(Content(), 10))

    def test_server_delay_survives_restart_and_cannot_be_shortened(self):
        with tempfile.TemporaryDirectory() as directory:
            record(directory, {"http_status": 503, "retry_after_seconds": 1727}, now=100)
            record(directory, {"http_status": 503, "retry_after_seconds": 20}, now=110)
            self.assertEqual(active(directory, now=120)["seconds_remaining"], 1707)
            self.assertIsNone(active(directory, now=1827))
            self.assertFalse((Path(directory) / "auth-cooldown.json").exists())

    def test_invalid_headers_are_not_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            for delay in (None, -1, True, "private@example.invalid", 2 ** 31):
                self.assertIsNone(record(directory, {"http_status": 503, "retry_after_seconds": delay}, now=0))
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_503_diagnostic_keeps_retry_date_without_body_or_credentials(self):
        trace = AuthTrace()
        trace.enter("people_key_request")
        with patch("research.auth_diagnostics.time.time", return_value=0):
            trace.http_response(503, "Thu, 01 Jan 1970 01:00:00 GMT")
        status = trace.failure(SearchPartyError("private@example.invalid secret-body"))
        self.assertEqual(status["reason"], "searchparty_unavailable")
        self.assertEqual(status["retry_after_seconds"], 3600)
        self.assertNotIn("private", json.dumps(status))
        self.assertNotIn("secret", json.dumps(status))

    def test_key_and_config_probes_stop_before_loading_credentials(self):
        try:
            from research.key_probe import acquire
            from research.searchparty_config import probe
        except ImportError:
            self.skipTest("Install auth and push-research extras")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            record(directory, {"http_status": 503, "retry_after_seconds": 1800})
            with patch("research.key_probe.restore") as key_restore, patch("research.searchparty_config.restore") as config_restore:
                status = asyncio.run(acquire(directory, AuthTrace(), {}))
                config = {}
                asyncio.run(probe(directory, config))
            key_restore.assert_not_called()
            config_restore.assert_not_called()
            self.assertEqual(status["reason"], "server_retry_after_active")
            self.assertEqual(config["reason"], "server_retry_after_active")
            self.assertFalse(status["network_request_attempted"])
