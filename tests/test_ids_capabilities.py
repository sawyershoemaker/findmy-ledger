import json
import unittest
from types import SimpleNamespace

from research.ids_capabilities import CAPABILITY, install_secure_location_capability, receiver_capabilities


class CapabilityTests(unittest.TestCase):
    def test_registration_enables_secure_locations_without_replacing_other_capabilities(self):
        original = {"supports-fmd-v2": True, "supports-findmy-plugin-messages": True}
        ids = SimpleNamespace(MULTIPLEX_CLIENT_DATA=original)
        install_secure_location_capability(ids)
        self.assertIs(ids.MULTIPLEX_CLIENT_DATA[CAPABILITY], True)
        self.assertTrue(ids.MULTIPLEX_CLIENT_DATA["supports-fmd-v2"])
        self.assertNotIn(CAPABILITY, original)

    def test_directory_capability_is_bound_to_this_receiver_and_no_secrets_escape(self):
        response = {"status": 0, "results": {"mailto:synthetic": {"identities": [
            {"push-token": b"other", "client-data": {CAPABILITY: True}},
            {"push-token": b"this", "client-data": {"secret": "synthetic-secret", CAPABILITY: False}},
        ]}}}
        actual = receiver_capabilities(response, "mailto:synthetic", b"this")
        self.assertFalse(actual[CAPABILITY])
        self.assertNotIn("secret", json.dumps(actual))
        response["results"]["mailto:synthetic"]["identities"][1]["client-data"][CAPABILITY] = True
        self.assertTrue(receiver_capabilities(response, "mailto:synthetic", b"this")[CAPABILITY])
        response["results"]["mailto:synthetic"]["identities"][0]["push-token"] = b"this"
        with self.assertRaises(ValueError):
            receiver_capabilities(response, "mailto:synthetic", b"this")
