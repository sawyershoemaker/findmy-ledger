"""Allowlisted authentication diagnostics. Never retain request/response bodies."""
from __future__ import annotations

import re
import time
from email.utils import parsedate_to_datetime


PHASES = frozenset({"startup", "local_input", "account_login", "gsa_init", "gsa_complete",
                    "apple_service_login", "two_factor_methods", "two_factor_request",
                    "two_factor_input", "two_factor_submit", "save_session", "prepare", "status",
                    "ids_validation", "ids_delegate", "ids_bag", "ids_certificate", "ids_handles", "ids_registration",
                    "people_key_setup", "people_key_request", "people_key_wait", "people_key_save", "searchparty_fetch"})
AUTH_MODES = frozenset({"secondaryAuth", "trustedDeviceSecondaryAuth"})


def status_number(value):
    if type(value) is int and -(2 ** 31) <= value < 2 ** 31:
        return value
    return None


def failure_reason(error):
    """Map known upstream failures to static categories; do not echo their text."""
    name = type(error).__name__
    if name == "InvalidCredentialsError":
        return "credential_challenge_rejected"
    if name in {"ClientConnectorCertificateError", "ClientConnectorSSLError", "SSLCertVerificationError", "TlsError"}:
        return "tls_verification_failed"
    if name in {"TimeoutError", "ServerTimeoutError", "ConnectionTimeoutError"}:
        return "network_timeout"
    if name == "KeyboardInterrupt":
        return "cancelled_locally"
    if name in {"ClientConnectorError", "ClientConnectionError", "ClientOSError"}:
        return "connection_failed"
    if name == "UnhandledProtocolError":
        message = str(error)  # Used only for classification inside this process.
        prefixes = {
            "Error response for GSA request: ": "gsa_http_error",
            "SMS 2FA request failed: ": "two_factor_http_error",
            "com.apple.mobileme login failed with status ": "apple_service_login_rejected",
            "This implementation only supports s2k and sk2_fo.": "unsupported_password_protocol",
            "Unknown auth value: ": "unsupported_authentication_step",
            "Unexpected state after submitting 2FA: ": "unexpected_state_after_two_factor",
        }
        if message == "Failed to process challenge":
            return "password_challenge_processing_failed"
        if message == "Failed to verify session":
            return "server_session_verification_failed"
        for prefix, category in prefixes.items():
            if message.startswith(prefix):
                return category
        return "unhandled_apple_protocol"
    if name in {"ValueError", "EOFError"}:
        return "invalid_or_missing_input"
    return "unexpected_local_error"


class AuthTrace:
    def __init__(self):
        self.initial_challenge_accepted = False
        self.enter("startup")

    def enter(self, phase):
        if phase not in PHASES:
            raise ValueError("Unrecognized authentication phase")
        self.phase = phase
        self.http_status = None
        self.apple_status = None
        self.apple_http_status = None
        self.authentication_step = None
        self.password_protocol = None
        self.retry_after_seconds = None

    def http_response(self, code, retry_after=None):
        if type(code) is int and 100 <= code <= 599:
            self.http_status = code
        if code in (429, 503) and isinstance(retry_after, str):
            try:
                if re.fullmatch(r"[0-9]{1,10}", retry_after.strip()):
                    seconds = int(retry_after)
                else:
                    seconds = int(parsedate_to_datetime(retry_after).timestamp() - time.time())
                if 0 <= seconds < 2 ** 31:
                    self.retry_after_seconds = seconds
            except (ValueError, TypeError, OverflowError):
                pass  # Raw header text must never enter the diagnostic output.

    def gsa_response(self, response):
        if not isinstance(response, dict):
            return
        status = response.get("Status")
        if isinstance(status, dict):
            self.apple_status = status_number(status.get("ec"))
            self.apple_http_status = status_number(status.get("hsc"))
            if self.phase == "gsa_init" and self.apple_status == 0:
                self.initial_challenge_accepted = True
            step = status.get("au")
            self.authentication_step = "none" if step is None else step if isinstance(step, str) and step in AUTH_MODES else "unsupported"
        if "sp" in response:
            protocol = response["sp"]
            self.password_protocol = protocol if isinstance(protocol, str) and protocol in {"s2k", "s2k_fo"} else "unsupported"

    def service_response(self, response):
        if not isinstance(response, dict):
            return
        delegates = response.get("delegates")
        mobileme = delegates.get("com.apple.mobileme") if isinstance(delegates, dict) else None
        status = mobileme.get("status") if isinstance(mobileme, dict) else None
        self.apple_status = status_number(response.get("status") if status is None else status)

    def failure(self, error):
        # Exception classes normally have fixed names, but use a conservative set.
        name = type(error).__name__
        known = {"UnhandledProtocolError", "InvalidCredentialsError", "TimeoutError", "ValueError",
                 "RuntimeError", "OSError", "FileExistsError", "FileNotFoundError", "KeyboardInterrupt",
                 "EOFError", "TypeError", "KeyError", "ModuleNotFoundError", "ImportError", "InvalidFileException",
                 "ClientConnectorCertificateError", "ClientConnectorSSLError", "SSLCertVerificationError",
                 "TlsError", "ServerTimeoutError", "ConnectionTimeoutError", "ClientConnectorError",
                 "ClientConnectionError", "ClientOSError", "SearchPartyError"}
        status = {"stage": "auth_probe", "phase": self.phase, "success": False,
                  "error_type": name if name in known else "UnexpectedError",
                  "reason": failure_reason(error), "http_status": self.http_status,
                  "apple_status": self.apple_status, "authentication_step": self.authentication_step,
                  "apple_http_status": self.apple_http_status,
                  "password_protocol": self.password_protocol,
                  "initial_challenge_accepted": self.initial_challenge_accepted,
                  "automatic_retry": False, "live_collection_ready": False}
        if name == "InvalidCredentialsError" and self.phase == "gsa_init":
            status["reason"] = "client_identity_rejected" if self.apple_status == -80045 else "initial_authentication_rejected"
        # Fallback for an HTTP exception that occurred before the response hook.
        if status["http_status"] is None and name == "UnhandledProtocolError":
            match = re.fullmatch(r"(?:Error response for GSA request|SMS 2FA request failed): ([1-5][0-9]{2})", str(error))
            if match:
                status["http_status"] = int(match[1])
        if status["http_status"] == 429:
            status["reason"] = "apple_http_429"
            status["retry_after_seconds"] = self.retry_after_seconds
        elif status["http_status"] == 503:
            status["retry_after_seconds"] = self.retry_after_seconds
        if name == "SearchPartyError":
            status["reason"] = ("searchparty_unavailable" if self.http_status == 503 else
                                "apple_http_429" if self.http_status == 429 else "searchparty_rejected")
        return status
