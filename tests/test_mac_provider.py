import base64
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

try:
    from research.mac_provider import MacProvider
except ImportError:
    MacProvider = None


@unittest.skipIf(MacProvider is None, "Optional authentication dependencies")
class MacProviderTests(unittest.IsolatedAsyncioTestCase):
    async def test_gateway_can_get_new_otp_inside_the_authentication_cache_window(self):
        identity = {"local_user_uuid": "synthetic-user", "device_id": "synthetic-device"}
        def response(otp):
            plain = json.dumps({"identity": identity, "headers": {"X-Apple-I-MD": otp, "X-Apple-Locale": "en_US"}}).encode()
            return SimpleNamespace(returncode=0, stdout=json.dumps({"protected_headers": base64.b64encode(plain).decode()}))
        with patch("research.mac_provider.load", return_value={"identity": identity}), \
             patch("research.mac_provider.transform", side_effect=lambda data, **kwargs: data), \
             patch("research.mac_provider.time.time", return_value=1000), \
             patch("research.mac_provider.subprocess.run", side_effect=[response("synthetic-first"), response("synthetic-second")]) as worker:
            provider = MacProvider("synthetic")
            first = await provider.get_headers("synthetic-user", "synthetic-device")
            cached = await provider.get_headers("synthetic-user", "synthetic-device")
            fresh = await provider.get_headers("synthetic-user", "synthetic-device", force_refresh=True)
            self.assertEqual(first["X-Apple-I-MD"], cached["X-Apple-I-MD"])
            self.assertNotEqual(first["X-Apple-I-MD"], fresh["X-Apple-I-MD"])
            self.assertEqual(worker.call_count, 2)
