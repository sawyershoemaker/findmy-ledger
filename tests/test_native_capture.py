import gzip
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from research.native_capture import MAX_BODY, TLS_CONTROL_HOST, TLS_CONTROL_PATH, TLS_CONTROL_BODY, NativeCapture, body_shape, endpoint, memory_certstore, request_summary


class NativeCaptureTests(unittest.TestCase):
    def test_tls_alert_categories_do_not_expose_raw_peer_or_error_text(self):
        capture = NativeCapture(MagicMock(), bind="10.0.0.2", client_ip="10.0.0.3", certificate_der=b"", output=None)
        capture.record = MagicMock()
        data = SimpleNamespace(context=SimpleNamespace(server=SimpleNamespace(address=("gateway.icloud.com", 443))),
                               conn=SimpleNamespace(error="SYNTHETIC_PRIVATE_PEER tlsv1 alert unknown ca"))
        capture.tls_failed_client(data)
        self.assertEqual(capture.record.call_args.args[0], {"event": "client_tls_failed", "target_service": True, "category": "unknown_ca"})
        data.conn.error = "SYNTHETIC_PRIVATE_PEER certificate verify failed"
        capture.tls_failed_server(data)
        self.assertEqual(capture.record.call_args.args[0]["category"], "certificate_verification_failed")
        self.assertNotIn("SYNTHETIC", str(capture.record.call_args_list))

    @unittest.skipIf(importlib.util.find_spec("mitmproxy") is None, "Run in the separate capture environment")
    def test_https_control_is_local_and_has_no_account_request_summary(self):
        capture = NativeCapture(MagicMock(), bind="10.0.0.2", client_ip="10.0.0.3", certificate_der=b"", output=None)
        capture.record = MagicMock()
        flow = SimpleNamespace(request=SimpleNamespace(scheme="https", host=TLS_CONTROL_HOST, path=TLS_CONTROL_PATH, method="GET"), response=None)
        capture.request(flow)
        self.assertEqual(flow.response.status_code, 200)
        self.assertEqual(flow.response.content, TLS_CONTROL_BODY)
        self.assertEqual(flow.response.headers["cache-control"], "no-store")
        capture.record.assert_called_once_with({"event": "https_control_passed"})
        flow.request.path = "/SYNTHETIC_PRIVATE_PATH"
        capture.request(flow)
        self.assertEqual(flow.response.status_code, 403)
        capture.record.assert_called_once()
        flow.request.scheme, flow.request.host, flow.request.path = "http", "10.0.0.2", capture.certificate_path
        capture.request(flow)
        self.assertEqual(flow.response.status_code, 200)
        self.assertEqual(flow.response.content, capture.certificate_der)
        self.assertEqual(flow.response.headers["cache-control"], "no-store")
        flow.request.path = "/temporary-probe.cer?probe=SYNTHETIC_OLD_CERTIFICATE"
        capture.request(flow)
        self.assertEqual(flow.response.status_code, 403)

    def test_repeated_phone_failures_keep_totals_without_ending_capture_early(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            master = MagicMock()
            capture = NativeCapture(master, bind="10.0.0.2", client_ip="10.0.0.3", certificate_der=b"", output=path)
            for _ in range(601):
                capture.record({"event": "certificate_downloaded"})
            for _ in range(397):
                capture.record({"event": "client_tls_failed", "target_service": True, "category": "unknown_ca"})
            capture.record({"event": "https_control_passed"})
            master.shutdown.assert_not_called()
            capture.stop("deadline")
            capture.finish()
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertLess(len(rows), 30)
            self.assertEqual(rows[-1]["event_counts"], {"certificate_downloaded": 601, "client_tls_failed": 397, "https_control_passed": 1})
            self.assertEqual(rows[-1]["reason"], "deadline")

    def test_record_limit_always_preserves_one_final_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            capture = NativeCapture(MagicMock(), bind="10.0.0.2", client_ip="10.0.0.3", certificate_der=b"", output=path)
            for _ in range(1001):
                capture.record({"event": "request_failed"})
            capture.finish()
            capture.finish()
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(len(rows), 1001)
            self.assertEqual(rows[-1]["reason"], "record_limit")
            self.assertEqual(rows[-1]["event_counts"], {"request_failed": 1001})
            capture.master.shutdown.assert_called_once()

    def test_credentials_identifiers_coordinates_and_unknown_keys_never_enter_summary(self):
        body = {"clientContext": {"apsToken": "SYNTHETIC_PUSH_SECRET", "deviceUDID": "SYNTHETIC_DEVICE",
            "signedInAs": "person@example.invalid", "selectedFriend": "SYNTHETIC_PERSON", "currentTime": 1793212345678},
            "serverContext": {"authToken": "SYNTHETIC_AUTH", "clientId": "SYNTHETIC_CLIENT"},
            "fetch": [{"fmId": "SYNTHETIC_PERSON", "ids": ["SYNTHETIC_LOCATION_ID"], "intent": "distributeKeys", "mode": "proactive"}],
            "SYNTHETIC_UNKNOWN_KEY": {"latitude": 40.01234, "longitude": -75.01234}}
        request = SimpleNamespace(host="p12-fmfmobile.icloud.com", method="POST",
            path="/fmipservice/friends/fmfd/SYNTHETIC_ACCOUNT/SYNTHETIC_DEVICE/initClient?private=SYNTHETIC_QUERY",
            headers={"Authorization": "Basic SYNTHETIC_HEADER_SECRET", "X-Apple-I-MD": "SYNTHETIC_ANISETTE"},
            raw_content=json.dumps(body).encode())
        result = request_summary(request)
        text = json.dumps(result)
        for sensitive in ("SYNTHETIC", "example.invalid", "40.01234", "75.01234", "1793212345678"):
            self.assertNotIn(sensitive, text)
        self.assertEqual(result["endpoint"], "friends_init")
        self.assertIn("distributeKeys", text)
        self.assertIn("milliseconds", text)
        self.assertEqual(result["headers_present"], ["Authorization", "X-Apple-I-MD"])

    def test_unexpected_host_and_path_are_never_echoed(self):
        self.assertIsNone(endpoint("gateway.icloud.com.evil.invalid", "/findmyservice/fetch"))
        self.assertIsNone(endpoint("setup.icloud.com", "/private"))
        self.assertEqual(endpoint("gateway.icloud.com", "/findmyservice/fetch?secret=value"), "searchparty_fetch")
        self.assertEqual(endpoint("gateway.icloud.com", "/SYNTHETIC_SECRET"), "other_gateway")
        self.assertEqual(endpoint(TLS_CONTROL_HOST, TLS_CONTROL_PATH), "tls_control")
        self.assertEqual(endpoint("gateway.icloud.com", TLS_CONTROL_PATH), "other_gateway")
        self.assertIsNone(endpoint(TLS_CONTROL_HOST + ".evil.invalid", TLS_CONTROL_PATH))

    def test_compressed_body_and_depth_are_bounded(self):
        self.assertEqual(body_shape(gzip.compress(b" " * (MAX_BODY + 1)), "gzip"), {"format": "too_large"})
        self.assertEqual(body_shape(b"SYNTHETIC_SECRET", "gzip"), {"format": "invalid_compression"})
        self.assertEqual(body_shape(b"SYNTHETIC_SECRET", "br"), {"format": "unsupported_compression"})
        deep = {"clientContext": {"clientContext": {"clientContext": {"clientContext": {
            "clientContext": {"clientContext": "SYNTHETIC_SECRET"}}}}}}
        result = json.dumps(body_shape(json.dumps(deep).encode(), ""))
        self.assertIn("depth_limit", result)
        self.assertNotIn("SYNTHETIC_SECRET", result)

    def test_client_and_destination_scope(self):
        capture = NativeCapture(MagicMock(), bind="10.0.0.2", client_ip="10.0.0.3", certificate_der=b"", output=None)
        capture.record = MagicMock()
        for address, allowed in (("10.0.0.3", True), ("10.0.0.4", False)):
            client = SimpleNamespace(peername=(address, 12345), error=None)
            capture.client_connected(client)
            self.assertEqual(client.error is None, allowed)
        for host, port, allowed in (("gateway.icloud.com", 443, True), ("gateway.icloud.com.evil.invalid", 443, False),
                                    ("10.0.0.1", 443, False), ("gateway.icloud.com", 80, False), (TLS_CONTROL_HOST, 443, False)):
            server = SimpleNamespace(address=(host, port), error=None)
            capture.server_connect(SimpleNamespace(server=server))
            self.assertEqual(server.error is None, allowed)

    @unittest.skipIf(importlib.util.find_spec("mitmproxy") is None, "Run in the separate capture environment")
    def test_certificate_private_key_is_not_written_and_ca_expires_in_one_day(self):
        from cryptography import x509
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            store, der = memory_certstore(directory)
            self.assertEqual({path.name for path in directory.iterdir()}, {"temporary-probe.cer", "public-dhparam.pem"})
            for path in directory.iterdir():
                self.assertNotIn(b"PRIVATE KEY", path.read_bytes())
            cert = x509.load_der_x509_certificate(der)
            self.assertLessEqual((cert.not_valid_after_utc - cert.not_valid_before_utc).total_seconds(), 86700)
            self.assertIsNotNone(store.default_privatekey)
