import unittest
import asyncio
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
try:
    from research.searchparty_config import config_summary
except ImportError:
    config_summary = None


@unittest.skipIf(config_summary is None, "Install the auth extra")
class ConfigSummaryTests(unittest.TestCase):
    def test_get_configuration_sends_no_body_or_location_identifier(self):
        from research.searchparty_config import probe
        class Content:
            async def iter_chunked(self, size):
                yield b'{"featureEnabled":true,"keyDistributionThrottle":300}'
        reply = SimpleNamespace(status=200, content=Content(), headers={})
        manager = MagicMock()
        manager.__aenter__ = AsyncMock(return_value=reply)
        manager.__aexit__ = AsyncMock(return_value=False)
        session = MagicMock()
        session.request.return_value = manager
        provider = SimpleNamespace(account_ids={"uid": "synthetic-user"},
            get_headers=AsyncMock(return_value={"X-Mme-Client-Info": "old-profile"}))
        client = SimpleNamespace(device_id="synthetic-device", product="SyntheticMac", os_version="13.1", build="22C65",
            login={"dsid": "123456", "mobileme_data": {"tokens": {"searchPartyToken": "synthetic-token"}}},
            http=SimpleNamespace(_get_session=AsyncMock(return_value=session), _ssl=object()), close=AsyncMock())
        with tempfile.TemporaryDirectory() as temporary, \
             patch("research.searchparty_config.restore", return_value=({}, provider)), \
             patch("research.searchparty_config.FriendsClient", return_value=client), \
             patch("research.searchparty_config.load", return_value={"device_id": "synthetic-device", "courier_token": "ab" * 32}):
            result = {}
            asyncio.run(probe(Path(temporary), result))
        self.assertTrue(result["success"])
        self.assertEqual(result["config"]["keyDistributionThrottle"], 300)
        self.assertEqual(session.request.call_args.args, ("GET", "https://gateway.icloud.com/findmyservice/config"))
        request = session.request.call_args.kwargs
        self.assertNotIn("json", request)
        self.assertNotIn("data", request)
        self.assertFalse(request["allow_redirects"])
        self.assertEqual(sum(name.lower() == "x-mme-client-info" for name in request["headers"]), 1)

    def test_only_known_numeric_config_values_are_exposed(self):
        result = config_summary({"statusCode": "200", "config": {"acceptVersion": "1", "featureEnabled": True,
            "keyDistributionThrottle": 3600, "private-person@example.invalid": "secret", "token": "private"}})
        self.assertEqual(result, {"statusCode": 200, "acceptVersion": 1, "featureEnabled": True, "keyDistributionThrottle": 3600})

    def test_untrusted_values_cannot_escape_in_known_fields(self):
        self.assertEqual(config_summary({"acceptVersion": "secret", "statusCode": "private-id",
            "overridePendingKeyRequestCheck": {"unexpected": "person@example.invalid"}}), {})
