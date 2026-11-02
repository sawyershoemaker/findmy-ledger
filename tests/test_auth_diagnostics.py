import json
import unittest
from unittest.mock import AsyncMock, patch

from research.auth_diagnostics import AuthTrace

try:
    from findmy import LoginState
    from findmy.errors import UnhandledProtocolError
    from findmy.util.http import HttpResponse, HttpSession
except ImportError:
    HttpSession = None
    UnhandledProtocolError = type("UnhandledProtocolError", (Exception,), {})


class DiagnosticTests(unittest.TestCase):
    def test_http_error_is_classified_without_raw_exception_text(self):
        trace = AuthTrace()
        trace.enter("gsa_init")
        status = trace.failure(UnhandledProtocolError("Error response for GSA request: 503"))
        self.assertEqual(status["phase"], "gsa_init")
        self.assertEqual(status["reason"], "gsa_http_error")
        self.assertEqual(status["http_status"], 503)

    def test_secrets_in_upstream_message_and_response_do_not_escape(self):
        trace = AuthTrace()
        trace.enter("gsa_complete")
        trace.gsa_response({"Status": {"ec": -22406, "em": "secret-token", "au": "secret-token"},
                            "sp": "secret-token", "account": "secret@example.invalid", "M2": b"secret-token"})
        error = UnhandledProtocolError("Unknown auth value: secret-token for secret@example.invalid")
        status = trace.failure(error)
        encoded = json.dumps(status)
        self.assertNotIn("secret-token", encoded)
        self.assertNotIn("secret@example.invalid", encoded)
        self.assertEqual(status["apple_status"], -22406)
        self.assertEqual(status["authentication_step"], "unsupported")
        self.assertEqual(status["password_protocol"], "unsupported")

    def test_message_with_extra_fields_cannot_forge_http_status(self):
        status = AuthTrace().failure(UnhandledProtocolError("Error response for GSA request: 503 secret-token"))
        self.assertIsNone(status["http_status"])
        self.assertNotIn("secret-token", json.dumps(status))

    def test_unexpected_types_do_not_become_diagnostic_data(self):
        trace = AuthTrace()
        trace.gsa_response({"Status": {"ec": "secret-token", "au": ["secret-token"]}, "sp": {"token": "secret-token"}})
        trace.http_response(True)
        status = trace.failure(ValueError("secret-token"))
        self.assertIsNone(status["apple_status"])
        self.assertIsNone(status["http_status"])
        self.assertNotIn("secret-token", json.dumps(status))

    def test_new_phase_does_not_reuse_previous_success_code(self):
        trace = AuthTrace()
        trace.enter("gsa_complete")
        trace.http_response(200)
        trace.gsa_response({"Status": {"ec": 0, "au": "trustedDeviceSecondaryAuth"}})
        trace.enter("two_factor_request")
        status = trace.failure(TimeoutError())
        self.assertIsNone(status["http_status"])
        self.assertIsNone(status["apple_status"])
        self.assertEqual(status["reason"], "network_timeout")

    def test_delegate_success_zero_is_preserved(self):
        trace = AuthTrace()
        trace.service_response({"delegates": {"com.apple.mobileme": {"status": 0}}})
        self.assertEqual(trace.apple_status, 0)

    def test_initial_identity_rejection_is_not_called_bad_password(self):
        trace = AuthTrace()
        trace.enter("gsa_init")
        trace.gsa_response({"Status": {"ec": -80045, "hsc": 200}})
        error = type("InvalidCredentialsError", (Exception,), {})("synthetic message")
        result = trace.failure(error)
        self.assertEqual(result["reason"], "client_identity_rejected")
        self.assertEqual(result["apple_http_status"], 200)

    def test_429_preserves_initial_success_and_only_numeric_retry_delay(self):
        trace = AuthTrace()
        trace.enter("gsa_init")
        trace.gsa_response({"Status": {"ec": 0}, "sp": "s2k"})
        trace.enter("gsa_complete")
        trace.http_response(429, "3600")
        trace.http_response(429)  # The response hook must not discard the header.
        result = trace.failure(UnhandledProtocolError("Error response for GSA request: 429"))
        self.assertTrue(result["initial_challenge_accepted"])
        self.assertEqual(result["retry_after_seconds"], 3600)
        self.assertEqual(result["reason"], "apple_http_429")

    def test_retry_after_date_and_invalid_header_are_not_echoed(self):
        trace = AuthTrace()
        with patch("research.auth_diagnostics.time.time", return_value=0):
            trace.http_response(429, "Thu, 01 Jan 1970 01:00:00 GMT")
        self.assertEqual(trace.retry_after_seconds, 3600)
        trace.enter("gsa_init")
        trace.http_response(429, "secret@example.invalid")
        result = trace.failure(RuntimeError("secret-token"))
        self.assertIsNone(result["retry_after_seconds"])
        self.assertNotIn("secret", json.dumps(result))


@unittest.skipIf(HttpSession is None, "Install the auth extra for integration tests")
class AccountHookTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from research.apple_account import make_account
        class Provider:
            client = "synthetic"
            get_cpd = AsyncMock(return_value={})
            get_headers = AsyncMock(return_value={})
            close = AsyncMock()
        self.trace = AuthTrace()
        self.account = make_account(Provider(), self.trace)
        self.addAsyncCleanup(self.account.close)

    async def test_live_request_hook_keeps_only_safe_gsa_fields(self):
        import plistlib
        response = HttpResponse(200, plistlib.dumps({"Response": {
            "Status": {"ec": -22406, "em": "secret-token"}, "sp": "s2k", "u": "secret@example.invalid"}}))
        with patch.object(HttpSession, "request", new=AsyncMock(return_value=response)):
            await self.account._gsa_request({"o": "init"})
        status = self.trace.failure(UnhandledProtocolError("synthetic failure"))
        self.assertEqual(status["http_status"], 200)
        self.assertEqual(status["apple_status"], -22406)
        self.assertEqual(status["phase"], "gsa_init")
        self.assertNotIn("secret", json.dumps(status))

    async def test_http_503_is_observed_before_upstream_raises(self):
        with patch.object(HttpSession, "request", new=AsyncMock(return_value=HttpResponse(503, b"secret-body"))):
            with self.assertRaises(UnhandledProtocolError) as caught:
                await self.account._gsa_request({"o": "init"})
        status = self.trace.failure(caught.exception)
        self.assertEqual(status["http_status"], 503)
        self.assertEqual(status["reason"], "gsa_http_error")
        self.assertNotIn("secret-body", json.dumps(status))

    async def test_bootstrap_survives_upstream_mobileme_transition(self):
        import plistlib
        self.account._username = "synthetic@example.invalid"
        self.account._set_login_state(LoginState.AUTHENTICATED, {"idms_pet": "synthetic-pet", "adsid": "synthetic-adsid"})
        response = HttpResponse(200, plistlib.dumps({"status": 0, "dsid": "synthetic-dsid",
            "delegates": {"com.apple.mobileme": {"status": 0, "service-data": {"tokens": {}}}}}))
        with patch.object(HttpSession, "request", new=AsyncMock(return_value=response)):
            state = await self.account._login_mobileme()
        self.assertEqual(state, LoginState.LOGGED_IN)
        self.assertEqual(self.account.bootstrap["idms_pet"], "synthetic-pet")
        self.assertNotIn("idms_pet", self.account._login_state_data)
        self.assertEqual(self.trace.phase, "apple_service_login")
        self.assertEqual(self.trace.apple_status, 0)

    async def test_two_factor_status_409_is_recognized_without_au(self):
        import plistlib
        response = HttpResponse(200, plistlib.dumps({"Response": {"Status": {"ec": 0, "hsc": 409}}}))
        with patch.object(HttpSession, "request", new=AsyncMock(return_value=response)):
            result = await self.account._gsa_request({"o": "complete"})
        self.assertEqual(result["Status"]["au"], "trustedDeviceSecondaryAuth")
        self.assertEqual(self.trace.apple_http_status, 409)

    async def test_rejected_login_is_not_promoted_to_two_factor(self):
        import plistlib
        response = HttpResponse(200, plistlib.dumps({"Response": {"Status": {"ec": -80045, "hsc": 409}}}))
        with patch.object(HttpSession, "request", new=AsyncMock(return_value=response)):
            result = await self.account._gsa_request({"o": "complete"})
        self.assertNotIn("au", result["Status"])

    async def test_known_trusted_device_flow_skips_sms_enumeration(self):
        self.account._account_info = {"trusted_device_2fa": True}
        self.account._set_login_state(LoginState.REQUIRE_2FA, {})
        with patch.object(HttpSession, "request", new=AsyncMock()) as http:
            methods = await self.account.get_2fa_methods()
        self.assertEqual(len(methods), 1)
        self.assertIn("TrustedDevice", type(methods[0]).__name__)
        http.assert_not_called()

    async def test_machine_identity_is_used_instead_of_random_account_ids(self):
        import plistlib
        from research.apple_account import make_account
        class Provider:
            client = "<test-model> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
            mobileme_client = "<test-model> <macOS;13.1;22C65> <com.apple.AOSKit/282 (com.apple.accountsd/113)>"
            account_ids = {"uid": "synthetic-uid", "devid": "synthetic-device"}
            get_cpd = AsyncMock(return_value={})
            get_headers = AsyncMock(return_value={})
            close = AsyncMock()
        provider = Provider()
        account = make_account(provider, AuthTrace())
        try:
            response = HttpResponse(200, plistlib.dumps({"Response": {"Status": {"ec": -20970}}}))
            with patch.object(HttpSession, "request", new=AsyncMock(return_value=response)) as http:
                await account._gsa_request({"o": "init"})
            provider.get_cpd.assert_awaited_once_with("synthetic-uid", "synthetic-device")
            headers = http.await_args.kwargs["headers"]
            client_headers = [value for key, value in headers.items() if key.lower() == "x-mme-client-info"]
            self.assertEqual(client_headers, [provider.client])
            self.assertEqual(headers["User-Agent"], "akd/1.0 CFNetwork/1404.0.5 Darwin/22.2.0")
        finally:
            await account.close()

    async def test_default_transport_rejects_untrusted_tls_certificate(self):
        import asyncio
        import ssl
        import tempfile
        from datetime import datetime, timedelta, timezone
        from pathlib import Path

        import aiohttp
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-untrusted.local")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(minutes=5)).sign(key, hashes.SHA256()))
        with tempfile.TemporaryDirectory() as tmp:
            cert_path, key_path = Path(tmp) / "cert.pem", Path(tmp) / "key.pem"
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_path, key_path)
            def connected(reader, writer):
                writer.close()
            server = await asyncio.start_server(connected, "127.0.0.1", 0, ssl=context)
            try:
                port = server.sockets[0].getsockname()[1]
                with self.assertRaises(aiohttp.ClientConnectorCertificateError):
                    await self.account._http.get(f"https://127.0.0.1:{port}/")
            finally:
                server.close()
                await server.wait_closed()


if __name__ == "__main__":
    unittest.main()
