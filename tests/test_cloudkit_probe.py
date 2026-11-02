import unittest
import importlib.util
from unittest.mock import patch

from research.cloudkit_probe import PEOPLE_CONTAINER, checked_cloudkit_url, local_provider


class CloudKitScopeTests(unittest.TestCase):
    @unittest.skipIf(importlib.util.find_spec("findmy") is None, "Optional authentication dependency")
    def test_fork_adapter_preserves_the_existing_machine_identity(self):
        identity = {"device_id": "SYNTHETIC_DEVICE", "local_user_uuid": "SYNTHETIC_USER", "client_info": "SYNTHETIC_CLIENT"}
        with patch("research.mac_provider.load", return_value={"identity": identity}):
            provider = local_provider("unused")
        self.assertEqual(provider.identity, identity)
        self.assertEqual(provider.account_ids, {"uid": "SYNTHETIC_USER", "devid": "SYNTHETIC_DEVICE"})
        self.assertEqual(provider.client, "SYNTHETIC_CLIENT")

    def test_only_people_container_and_read_operations_can_receive_tokens(self):
        for suffix in ["/setup/setup/ck/v1/ckAppInit?container=" + PEOPLE_CONTAINER,
                       "/ckdatabase/api/client/zone/retrieve", "/ckdatabase/api/client/record/sync"]:
            value = "https://gateway.icloud.com" + suffix
            self.assertEqual(checked_cloudkit_url(value), value)
        for value in ["http://gateway.icloud.com/ckdatabase/api/client/zone/retrieve",
            "https://gateway.icloud.com.evil.invalid/ckdatabase/api/client/zone/retrieve",
            "https://user@gateway.icloud.com/ckdatabase/api/client/zone/retrieve",
            "https://gateway.icloud.com:444/ckdatabase/api/client/zone/retrieve",
            "https://gateway.icloud.com/setup/setup/ck/v1/ckAppInit?container=com.apple.security.keychain",
            "https://gateway.icloud.com/ckdatabase/api/client/record/save",
            "https://gateway.icloud.com/ckdatabase/api/client/record/delete",
            "https://gateway.icloud.com/ckdatabase/api/client/record/sync?secret=value"]:
            with self.assertRaises(ValueError):
                checked_cloudkit_url(value)
