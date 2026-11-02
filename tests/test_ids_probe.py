import gzip
import io
import json
import plistlib
import unittest
import urllib.error
import urllib.request
from email.message import Message
from types import SimpleNamespace
from unittest.mock import Mock, patch

try:
    from research.auth_diagnostics import AuthTrace
    from research.ids_probe import approved_url, delegate_body, install_verified_transport, response_diagnostics
    from research.nac_worker import machine_profile
    import findmy
except ImportError:
    findmy = None


@unittest.skipIf(findmy is None, "Install the auth extra")
class IDSTests(unittest.TestCase):
    def test_signin_v2_wire_field_names_match_reference_protocol(self):
        body = plistlib.loads(delegate_body("SYNTHETIC-CLIENT"))
        self.assertEqual(set(body), {"delegates", "protocolVersion", "userInfo"})
        self.assertEqual(body["userInfo"]["client-id"], "SYNTHETIC-CLIENT")
        self.assertEqual(body["delegates"]["com.apple.private.ids"]["protocol-version"], "4")

    def test_error_diagnostics_omit_secrets_in_json_and_compressed_plist(self):
        secret = "synthetic-password-and-identifier"
        payload = {"status": 17, "localizedError": "UNAUTHORIZED", "description": secret,
                   "serviceErrors": [{"code": secret}], secret: secret,
                   "delegates": {"com.apple.private.ids": {"status": -23, "service-data": secret}}}
        for body in (json.dumps(payload).encode(), gzip.compress(plistlib.dumps(payload))):
            trace = AuthTrace()
            response_diagnostics(trace, body, {"scnt": secret})
            output = json.dumps(trace.ids_diagnostic)
            self.assertNotIn(secret, output)
            self.assertEqual(trace.apple_status, -23)
            self.assertEqual(trace.ids_diagnostic["service_error"], "unauthorized")
            self.assertTrue(trace.ids_diagnostic["challenge_headers_present"])
        response_diagnostics(trace, b"<html>synthetic-secret</html>", {})
        self.assertEqual(trace.ids_diagnostic["response_format"], "unrecognized")
        self.assertNotIn("service_error", trace.ids_diagnostic)

    def test_ids_destinations_and_redirects_are_restricted(self):
        approved_url("https://setup.icloud.com/setup/signin/v2/login")
        for value in ("http://setup.icloud.com/", "https://setup.icloud.com.evil.invalid/",
                      "https://secret@setup.icloud.com/", "https://setup.icloud.com:444/"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                approved_url(value)
        ids, trace = SimpleNamespace(), AuthTrace()
        with patch("research.ids_probe.urllib.request.build_opener") as builder:
            install_verified_transport(ids, trace)
            tls, redirects = builder.call_args.args
            import ssl
            self.assertEqual(tls._context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(tls._context.check_hostname)
            self.assertIsNone(redirects.redirect_request(None, None, 302, "", {}, "https://evil.invalid"))
            with self.assertRaises(ValueError):
                ids._urlopen("https://evil.invalid", timeout=1)
            builder.return_value.open.assert_not_called()

    def test_http_failure_diagnostics_preserve_body_and_do_not_retry(self):
        payload = plistlib.dumps({"status": 12, "localizedError": "UNAUTHORIZED"})
        headers = Message()
        headers["Retry-After"] = "90"
        error = urllib.error.HTTPError("https://setup.icloud.com/setup/signin/v2/login", 429,
                                       "Too many requests", headers, io.BytesIO(payload))
        ids, trace = SimpleNamespace(), AuthTrace()
        with patch("research.ids_probe.urllib.request.build_opener") as builder:
            builder.return_value.open.side_effect = error
            install_verified_transport(ids, trace)
            with self.assertRaises(urllib.error.HTTPError) as caught:
                ids._urlopen(error.url, timeout=1)
            self.assertEqual(caught.exception.read(), payload)
            self.assertEqual(trace.apple_status, 12)
            self.assertEqual(trace.retry_after_seconds, 90)
            builder.return_value.open.assert_called_once()

    def test_validation_profile_reuses_mac_identity_without_mutating_template(self):
        template = {"iokit": {"IOPlatformUUID": "old", "product-name": b"OldMac"}}
        identity = {"client_info": "<MacBookPro13,2> <macOS;13.1;22C65>",
                    "host_uuid": "00000000000000000000000000000001", "serial": "SYNTHETIC001"}
        encode_value = Mock(side_effect=lambda value: b"synthetic-encoded:" + value)
        actual = machine_profile(template, identity, encode_value)
        self.assertEqual(actual["iokit"]["IOPlatformUUID"], "00000000-0000-0000-0000-000000000001")
        self.assertEqual(actual["iokit"]["IOPlatformSerialNumber"], "SYNTHETIC001")
        self.assertEqual(actual["iokit"]["board-id"], b"Mac-66E35819EE2D0D05\0")
        self.assertEqual(actual["iokit"]["Gq3489ugfi"], b"synthetic-encoded:SYNTHETIC001")
        self.assertEqual(actual["iokit"]["Fyp98tpgj"], b"synthetic-encoded:" + bytes(15) + b"\x01")
        self.assertEqual(template["iokit"]["IOPlatformUUID"], "old")
        with self.assertRaises(ValueError):
            machine_profile(template, {**identity, "client_info": "<OtherMac>"}, encode_value)
