"""Register only the Find My IDS service, keeping state in the Windows DPAPI store."""
import argparse
import asyncio
import base64
import copy
import gzip
import io
import json
import logging
import plistlib
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit
from uuid import uuid4

from .auth_cooldown import active, record
from .auth_diagnostics import AuthTrace, status_number
from .saved_session import restore
from .windows_secrets import load, save_atomic


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def approved_url(value):
    url = urlsplit(value)
    if (url.scheme != "https" or url.username or url.password or url.port not in (None, 443)
            or url.hostname not in {"setup.icloud.com", "init.ess.apple.com", "profile.ess.apple.com",
                                    "identity.ess.apple.com", "registration.ess.apple.com"}):
        raise ValueError("Unexpected IDS service destination")
    return value


def response_diagnostics(trace, body, headers):
    """Inspect service failures locally; export only fixed categories and numbers."""
    detail = {"response_format": "empty" if not body else "unrecognized",
              "response_bytes": len(body), "challenge_headers_present":
              bool(headers.get("scnt") or headers.get("X-Apple-ID-Session-Id"))}
    decoded = None
    try:
        if body.startswith(b"\x1f\x8b"):
            with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:
                body = stream.read(1024 * 1024 + 1)
        if len(body) <= 1024 * 1024:
            try:
                decoded = plistlib.loads(body)
                detail["response_format"] = "plist"
            except (ValueError, TypeError, plistlib.InvalidFileException):
                try:
                    decoded = json.loads(body)
                    detail["response_format"] = "json"
                except (ValueError, UnicodeError):
                    pass
    except (OSError, EOFError):
        pass
    if isinstance(decoded, dict):
        known = {"status", "delegates", "error", "localizedError", "localized-error",
                 "description", "message", "Status", "authType", "serviceErrors", "protocolVersion"}
        detail["response_known_fields"] = sorted(known.intersection(decoded))
        trace.apple_status = status_number(decoded.get("status"))
        delegates = decoded.get("delegates")
        delegate = delegates.get("com.apple.private.ids") if isinstance(delegates, dict) else None
        if isinstance(delegate, dict) and status_number(delegate.get("status")) is not None:
            trace.apple_status = delegate["status"]
        categories = {"UNAUTHORIZED": "unauthorized", "AUTHENTICATION_FAILED": "authentication_failed",
                      "MISSING_REQUIRED_FIELD": "missing_required_field", "INVALID_REQUEST": "invalid_request",
                      "TERMS_NOT_ACCEPTED": "terms_not_accepted", "ACCOUNT_REPAIR_NEEDED": "account_repair_needed",
                      "MOBILEME_TERMS_OF_SERVICE_UPDATE": "terms_update",
                      "MOBILEME_ACCOUNT_NOT_FOUND": "account_not_found",
                      "ICLOUD_UNSUPPORTED_DEVICE": "unsupported_device"}
        for field in ("error", "localizedError", "localized-error"):
            value = decoded.get(field)
            if isinstance(value, str) and value in categories:
                detail["service_error"] = categories[value]
        description = decoded.get("description", "")
        message = decoded.get("message", "")
        detail["terms_acceptance_required"] = isinstance(description, str) and description.strip().lower() in {
            "this account needs to accept the tos", "this account needs to accept the tos."}
        detail["identity_verification_required"] = isinstance(message, str) and (
            "to sign in, you must verify your identity" in message.lower())
        detail["terms_dialog"] = decoded.get("DialogType") == "TOSDialog"
    trace.ids_diagnostic = detail
    if trace.http_status and trace.http_status >= 400 and isinstance(decoded, dict):
        protected_error_path = getattr(trace, "protected_error_path", None)
        if protected_error_path:
            # Retain only the two diagnostic fields, encrypted, so adding a
            # category later does not require another account request.
            fields = {name: decoded[name] for name in ("localizedError", "description")
                      if isinstance(decoded.get(name), str)}
            save_atomic(protected_error_path, {"phase": trace.phase, "http_status": trace.http_status,
                                             "error_fields": fields})


def delegate_body(client_id):
    # signin/v2 uses camelCase at the outer level, but kebab-case inside
    # userInfo and each delegate. See rustpush V2AuthRequest/V2AuthUserInfo.
    return plistlib.dumps({"delegates": {"com.apple.private.ids": {"protocol-version": "4"}},
                           "protocolVersion": "1.0", "userInfo": {"client-id": client_id,
                           "language": "en-US", "timezone": "America/New_York"}}, fmt=plistlib.FMT_XML)


def install_delegate_login(ids, route="signin_v2", client_id=None, *, cached=None, on_success=None):
    if route not in {"signin_v2", "iosbuddy"}:
        raise ValueError("Unsupported delegate route")
    def login(*, username, idms_pet, adsid, anisette_headers, device, validation_data):
        if cached is not None:
            return copy.deepcopy(cached)
        headers = dict(anisette_headers)
        headers.update({"Accept-Encoding": "gzip", "Content-Type": "application/x-apple-plist",
                        "User-Agent": "com.apple.iCloudHelper/282 CFNetwork/1404.0.5 Darwin/22.2.0",
                        "X-Apple-ADSID": adsid, "X-Mme-Client-Info": ids._mme_client_info(device)})
        if route == "signin_v2":
            headers["X-Mme-Nas-Qualify"] = base64.b64encode(validation_data).decode("ascii")
            path, body = "signin/v2/login", delegate_body(str(uuid4()).upper())
        else:
            # Same PET delegate broker already used by the successful account
            # login. This is a separate explicit route, never an automatic retry.
            path = "iosbuddy/loginDelegates"
            body = plistlib.dumps({"apple-id": username, "password": idms_pet,
                                   "client-id": client_id or str(uuid4()).upper(),
                                   "delegates": {"com.apple.private.ids": {"protocol-version": "4"}}})
        response = ids._request_plist("https://setup.icloud.com/setup/" + path, headers=headers,
                                      body=body, auth=(username, idms_pet))
        delegates = response.get("delegates")
        delegate = delegates.get("com.apple.private.ids") if isinstance(delegates, dict) else None
        if response.get("status") != 0 or not isinstance(delegate, dict) or delegate.get("status") != 0:
            raise ids.IDSRegistrationError("IDS delegate did not accept the request")
        data = delegate.get("service-data")
        if not isinstance(data, dict) or not data.get("profile-id") or not data.get("auth-token"):
            raise ids.IDSRegistrationError("IDS delegate response is incomplete")
        if on_success:
            on_success(data)
        return data
    ids._login_ids_delegate = login


def install_verified_transport(ids, trace):
    from .ids_tls import trust_context
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=trust_context()), NoRedirect())

    class Reply(io.BytesIO):
        def __init__(self, body, status, headers):
            super().__init__(body)
            self.status, self.headers = status, headers

    def open_verified(request, *, timeout):
        raw = getattr(request, "full_url", request)
        approved_url(raw)
        if isinstance(request, str):
            request = urllib.request.Request(request)
        path = urlsplit(raw).path
        phase = ("ids_delegate" if path.endswith(("/signin/v2/login", "/iosbuddy/loginDelegates")) else "ids_bag" if path.endswith("/getBag")
                 else "ids_certificate" if "authenticateDS" in path else "ids_handles" if "getHandles" in path
                 else "ids_registration")
        trace.enter(phase)
        trace.ids_diagnostic = {}
        if phase == "ids_delegate":
            request.add_header("User-Agent", "com.apple.iCloudHelper/282 CFNetwork/1404.0.5 Darwin/22.2.0")
        request.add_header("Connection", "close")
        try:
            with opener.open(request, timeout=timeout) as response:
                body = response.read()
                trace.http_response(response.status, response.headers.get("Retry-After"))
                response_diagnostics(trace, body, response.headers)
                return Reply(body, response.status, response.headers)
        except urllib.error.HTTPError as error:
            trace.http_response(error.code, error.headers.get("Retry-After"))
            body = error.read()
            response_diagnostics(trace, body, error.headers)
            # Preserve the in-process parser's stream; never log the body.
            raise urllib.error.HTTPError(error.url, error.code, error.reason, error.headers,
                                         io.BytesIO(body)) from None
        except urllib.error.URLError as error:
            import ssl
            if isinstance(error.reason, ssl.SSLCertVerificationError):
                trace.ids_diagnostic = {"tls_verification_failed": True,
                                        "tls_verify_code": status_number(error.reason.verify_code)}
            raise

    ids._urlopen = open_verified


def fresh_validation(state_dir, device_id):
    path = state_dir / "nac-validation.dpapi"
    saved = load(path) if path.exists() else {}
    age = time.time() - saved.get("created_at", 0)
    if saved.get("device_id") != device_id or saved.get("profile_encoding_version") != 2 or not 0 <= age < 120:
        result = subprocess.run([sys.executable, "-m", "research.nac_worker", "--state-dir", str(state_dir.resolve())],
                                cwd=Path(__file__).resolve().parent.parent, capture_output=True, text=True,
                                timeout=90, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if result.returncode != 0:
            raise RuntimeError("Local IDS validation generation failed")
        saved = load(path)
    if (saved.get("device_id") != device_id or saved.get("profile_encoding_version") != 2
            or not 0 <= time.time() - saved.get("created_at", 0) < 120):
        raise ValueError("IDS validation is stale or for a different machine")
    return saved


async def register(state_dir, trace, delegate_route="signin_v2"):
    state_dir = Path(state_dir).resolve()
    trace.protected_error_path = state_dir / "ids-error.dpapi"
    config = json.loads((state_dir / "push-helper-config.json").read_text())
    if config["onitrack_commit"] != "04dd25312643d8c9aa93c883a343488a4b682635":
        raise ValueError("Unexpected IDS implementation revision")
    sys.path.insert(0, config["onitrack_path"])
    from onitrack import ids
    from .ids_capabilities import install_secure_location_capability
    install_secure_location_capability(ids)
    install_verified_transport(ids, trace)
    state, provider = restore(state_dir)
    delegate_path = state_dir / "ids-delegate.dpapi"
    cached = load(delegate_path) if delegate_path.exists() else {}
    binding = {"device_id": provider.identity["device_id"], "account_dsid": state["login"]["data"]["dsid"]}
    use_cache = (all(cached.get(key) == value for key, value in binding.items())
                 and cached.get("route") == delegate_route and 0 <= time.time() - cached.get("created_at", 0) < 600)
    def save_delegate(data):
        save_atomic(delegate_path, {**binding, "route": delegate_route, "created_at": time.time(), "delegate": data})
    install_delegate_login(ids, delegate_route, provider.account_ids["uid"],
                           cached=cached.get("delegate") if use_cache else None, on_success=save_delegate)
    destination = state_dir / "ids.dpapi"
    existing = load(destination) if destination.exists() else {}
    try:
        machine = provider.identity
        if existing.get("device_id") not in (None, machine["device_id"]):
            raise ValueError("IDS identity belongs to a different machine")
        if existing.get("registered"):
            return status_summary(existing)
        trace.enter("ids_validation")
        validation = await asyncio.to_thread(fresh_validation, state_dir, machine["device_id"])
        device = SimpleNamespace(display_name="FindMy Ledger (Windows)", product_type="MacBookPro13,2", os_version="13.1",
                                 os_build="22C65", udid=machine["device_id"], fmf_udid=machine["device_id"],
                                 serial_number=machine["serial"], software_name="macOS")
        external = {"validation_data": validation["validation_data"], "device_info": {
            "hardware_version": device.product_type, "software_version": device.os_version,
            "software_build_id": device.os_build, "software_name": device.software_name,
            "unique_device_id": device.udid, "serial_number": device.serial_number}}
        existing.update({"device_id": machine["device_id"], "external_validation": external, "uses_local_udid": True})
        if not existing.get("identity"):
            existing["identity"] = ids._load_or_create_identity({}).export_state()
        save_atomic(destination, existing)
        account_state = copy.deepcopy(state)
        account_state["login"]["data"].update(state["protocol_bootstrap"])
        headers = await provider.get_headers(provider.account_ids["uid"], provider.account_ids["devid"])
        push = load(state_dir / "apns.dpapi")
        if push.get("device_id") != machine["device_id"]:
            raise ValueError("Push identity belongs to a different machine")
        result = await asyncio.to_thread(ids.register_ids, account_state=account_state, apns_state=push,
                                         anisette_headers=headers, device=device, existing=existing)
        result.ids_state["device_id"] = machine["device_id"]
        result.ids_state["secure_location_capability_advertised"] = True
        # Validation is short-lived. Its most recent copy remains in its dedicated encrypted file.
        result.ids_state.pop("external_validation", None)
        result.ids_state["device_profile_details"] = external["device_info"]
        save_atomic(destination, result.ids_state)
        return status_summary(result.ids_state)
    finally:
        await provider.close()


def status_summary(state):
    return {"stage": "ids_registration", "success": bool(state.get("registered")),
            "ids_registered": bool(state.get("registered")), "registered_user_count": len(state.get("users", {})),
            "state_saved_encrypted": True, "people_key_received": False, "live_collection_ready": False}


def failure_summary(trace, error):
    result = trace.failure(error)
    result["stage"] = "ids_registration"
    result.update(getattr(trace, "ids_diagnostic", {}))
    if type(error).__name__ == "IDSRegistrationError":
        result["error_type"] = "IDSRegistrationError"
        if trace.http_status != 429:
            result["reason"] = "ids_service_rejected"
        if type(getattr(error, "apple_status", None)) is int:
            result["apple_status"] = error.apple_status
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--delegate-route", choices=("signin_v2", "iosbuddy"), default="signin_v2")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    trace = AuthTrace()
    try:
        cooldown = active(args.state_dir)
        if cooldown:
            print(json.dumps(cooldown, indent=2))
            return 2
        result = asyncio.run(register(args.state_dir, trace, args.delegate_route))
    except (Exception, KeyboardInterrupt) as error:
        result = failure_summary(trace, error)
        cooldown = record(args.state_dir, result)
        if cooldown:
            result["retry_not_before_utc"] = cooldown["retry_not_before_utc"]
    result["delegate_route"] = args.delegate_route
    (args.state_dir / "ids-status.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result.get("success") else 2


if __name__ == "__main__":
    raise SystemExit(main())
