"""Temporary request-shape capture; no credentials, contacts, or location output.

Run in the separate capture environment (mitmproxy 12.2.1). The temporary CA
private key exists only in memory. No traffic dump or system proxy is installed.
"""
import argparse
import asyncio
import datetime
import gzip
import hashlib
import io
import ipaddress
import json
import logging
import re
import time
from pathlib import Path
from unittest.mock import patch

from .connect_probe import apple_host

MAX_BODY = 2 * 1024 * 1024
TLS_CONTROL_HOST = "findmy-ledger.invalid"
TLS_CONTROL_PATH = "/__findmy_ledger_tls_control__"
TLS_CONTROL_BODY = b"FindMy Ledger HTTPS trust check passed.\n"
REPEATED_EVENTS = frozenset({"certificate_downloaded", "health_check", "client_tls_failed", "server_tls_failed", "client_outside_scope"})
CAPTURE_HOST = re.compile(r"(?:(?:p[0-9]{1,3}-)?fmfmobile\.icloud\.com|gateway\.icloud\.com)\Z")
KNOWN_FIELDS = frozenset({
    "clientContext", "serverContext", "dataContext", "fetch", "fmId", "intent", "mode", "ids",
    "apsToken", "clientId", "contextApp", "shallowStats", "liveStats", "nearbyWatchIdentifiers",
    "appName", "appVersion", "buildVersion", "countryCode", "currentTime", "deviceClass",
    "deviceHasPasscode", "deviceUDID", "fencingEnabled", "isFMFAppRemoved", "osVersion", "platform",
    "processId", "productType", "regionCode", "selectedFriend", "signedInAs", "timezone", "unlockState",
    "authToken", "prsId", "deviceDisplayName", "appPushModeAllowed", "frontMostWindow", "legacyFallbackData",
    "limitedPrecision", "liveSessionStatistics", "pushMode", "tabs", "windowVisible", "push", "fmly",
    "isDaemon", "callbackIntervalInMS", "minCallbackIntervalInMS", "maxCallbackIntervalInMS",
    "callerHandleId", "contextBundleApp",
})
ENUMS = {
    "intent": {"distributeKeys", "startLocationUpdates", "heal", "stopLocationUpdates"},
    "mode": {"proactive", "shallow", "live"},
    "contextApp": {"com.apple.findmy.findmylocated", "com.apple.findmy", "com.apple.findmy.findmylocateagent"},
    "contextBundleApp": {"com.apple.findmy.findmylocated", "com.apple.findmy", "com.apple.findmy.findmylocateagent"},
    "appName": {"fmfd", "FindMy", "findmy", "findmylocated"}, "deviceClass": {"iPhone", "Mac", "iPad"},
    "platform": {"iphone", "iOS", "macosx"},
}
HEADERS = ("Authorization", "X-Apple-AuthScheme", "X-Apple-Find-API-Ver", "X-FMF-Model-Version",
           "X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO", "X-MMe-Client-Info",
           "X-Mme-Device-Id", "X-Apple-DSID", "X-Apple-ADSID", "Accept-Version", "Content-Type")


def shape(value, *, field=None, depth=0):
    """Fixed key allowlist; arbitrary strings and map keys can never reach logs."""
    if depth > 5:
        return {"type": "depth_limit"}
    if isinstance(value, dict):
        return {"type": "object", "fields": {key: shape(item, field=key, depth=depth + 1)
                for key, item in value.items() if key in KNOWN_FIELDS},
                "other_field_count": sum(key not in KNOWN_FIELDS for key in value)}
    if isinstance(value, list):
        return {"type": "array", "count": len(value), "items": [shape(item, depth=depth + 1) for item in value[:3]]}
    if value is None:
        return {"type": "null"}
    if type(value) is bool:
        return {"type": "boolean", "value": value}
    if type(value) in (int, float):
        result = {"type": "number"}
        if field == "currentTime":
            result["unit_hint"] = "milliseconds" if 1e12 < value < 1e14 else "seconds" if 1e9 < value < 1e11 else "other"
        return result
    if isinstance(value, str):
        result = {"type": "string", "length": len(value)}
        if value in ENUMS.get(field, ()):
            result["protocol_literal"] = value
        if field in {"apsToken", "deviceUDID"}:
            result["hex_encoding"] = bool(re.fullmatch(r"[0-9a-fA-F]+", value))
        return result
    return {"type": "other"}


def endpoint(host, path):
    if host == TLS_CONTROL_HOST and path == TLS_CONTROL_PATH:
        return "tls_control"
    if not CAPTURE_HOST.fullmatch(host):
        return None
    path = path.split("?", 1)[0]
    if host == "gateway.icloud.com":
        return "searchparty_fetch" if path == "/findmyservice/fetch" else "other_gateway"
    for suffix, name in (("/minCallback/selFriend/refreshClient", "friends_selected_refresh"),
                         ("/minCallback/refreshClient", "friends_refresh"), ("/initClient", "friends_init")):
        if path.endswith(suffix):
            return name
    return "other_friends"


def tls_failure_category(error):
    """Fixed TLS alert categories only; peer names and raw errors stay private."""
    if not isinstance(error, str) or len(error) > 4096:
        return "other"
    text = error.lower()
    for phrase, category in (("unknown ca", "unknown_ca"), ("bad certificate", "bad_certificate"),
            ("certificate unknown", "certificate_rejected"), ("certificate verify failed", "certificate_verification_failed"),
            ("does not trust", "certificate_trust_rejected"), ("handshake failure", "handshake_failure"),
            ("unsupported protocol", "protocol_mismatch"), ("connection reset", "connection_reset")):
        if phrase in text:
            return category
    return "other"


def body_shape(raw, encoding):
    if not isinstance(raw, bytes) or len(raw) > MAX_BODY:
        return {"format": "too_large"}
    if encoding == "gzip":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                raw = stream.read(MAX_BODY + 1)
        except (OSError, EOFError):
            return {"format": "invalid_compression"}
    elif encoding not in ("", "identity"):
        return {"format": "unsupported_compression"}
    if len(raw) > MAX_BODY:
        return {"format": "too_large"}
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        return {"format": "non_json"}
    return {"format": "json", "shape": shape(data)}


def request_summary(request):
    route = endpoint(request.host, request.path)
    if route is None:
        return None
    return {"event": "request_shape", "endpoint": route,
            "method": request.method if request.method in {"GET", "POST"} else "other",
            "headers_present": [name for name in HEADERS if name in request.headers],
            "body": body_shape(request.raw_content, request.headers.get("content-encoding", ""))}


class NativeCapture:
    def __init__(self, master, *, bind, client_ip, certificate_der, output):
        self.master, self.bind, self.client_ip = master, bind, client_ip
        self.certificate_der, self.output = certificate_der, output
        self.count = 0
        self.event_counts = {}
        self.repeated_counts = {}
        self.stop_reason = None
        self.finished = False
        self.certificate_id = hashlib.sha256(certificate_der).hexdigest()[:16]
        self.certificate_path = "/temporary-probe.cer?probe=" + self.certificate_id

    def stop(self, reason):
        self.stop_reason = self.stop_reason or reason
        self.master.shutdown()

    def write(self, entry):
        with self.output.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"observed_at": int(time.time()), **entry}, separators=(",", ":")) + "\n")

    def record(self, entry):
        event = entry["event"]
        self.event_counts[event] = self.event_counts.get(event, 0) + 1
        if event in REPEATED_EVENTS:
            # TLS rejection and profile-download retries flooded the first phone
            # control. Retain exact totals, writing repetitions at powers of two.
            signature = json.dumps(entry, sort_keys=True, separators=(",", ":"))
            occurrences = self.repeated_counts.get(signature, 0) + 1
            self.repeated_counts[signature] = occurrences
            if occurrences & (occurrences - 1):
                return
            entry = {**entry, "occurrences": occurrences}
        if self.count >= 1000:
            self.stop("record_limit")
            return
        self.count += 1
        self.write(entry)

    def finish(self):
        if not self.finished:
            self.finished = True
            # Always reserve this one final record, even after the event cap.
            self.write({"event": "probe_stopped", "reason": self.stop_reason or "shutdown",
                        "event_counts": self.event_counts, "event_records": self.count})

    def client_connected(self, client):
        if not client.peername or client.peername[0] != self.client_ip:
            client.error = "Client outside probe scope"
            self.record({"event": "client_outside_scope"})

    def http_connect(self, flow):
        from mitmproxy import http
        host = flow.request.host.lower()
        if flow.request.port != 443 or not (apple_host(host) or host == TLS_CONTROL_HOST):
            flow.response = http.Response.make(403, b"Outside probe scope")

    def server_connect(self, data):
        host, port = data.server.address
        # The reserved control name must never resolve or reach an upstream.
        if host.lower() == TLS_CONTROL_HOST or port != 443 or not apple_host(host.lower()):
            data.server.error = "Destination outside probe scope"

    def request(self, flow):
        from mitmproxy import http
        request = flow.request
        if request.scheme == "https" and request.host == TLS_CONTROL_HOST:
            # Use a neutral reserved name, not an Apple domain with additional
            # trust policies. Every path is local; no DNS/upstream is required.
            if request.path == TLS_CONTROL_PATH and request.method == "GET":
                flow.response = http.Response.make(200, TLS_CONTROL_BODY,
                    {"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store"})
                self.record({"event": "https_control_passed"})
            else:
                flow.response = http.Response.make(403, b"Outside probe scope")
            return
        if request.scheme == "http":
            local = request.host in {self.bind, "127.0.0.1", "localhost"}
            if local and request.path == "/health":
                flow.response = http.Response.make(200, b"Find My request-shape probe is reachable.\n", {"Content-Type": "text/plain", "Cache-Control": "no-store"})
                self.record({"event": "health_check"})
            elif local and request.path in {"/temporary-probe.cer", self.certificate_path}:
                flow.response = http.Response.make(200, self.certificate_der,
                    {"Content-Type": "application/x-x509-ca-cert", "Cache-Control": "no-store",
                     "Content-Disposition": f'attachment; filename="temporary-probe-{self.certificate_id}.cer"'})
                self.record({"event": "certificate_downloaded"})
            else:
                flow.response = http.Response.make(403, b"Outside probe scope")
            return
        result = request_summary(request)
        if result:
            self.record(result)

    def responseheaders(self, flow):
        # Responses can contain locations. Forward them without retaining bodies.
        flow.response.stream = True
        route = endpoint(flow.request.host, flow.request.path)
        if route:
            self.record({"event": "response_status", "endpoint": route, "status": flow.response.status_code})

    def tls_failed_client(self, data):
        host = data.context.server.address[0] if data.context.server.address else ""
        self.record({"event": "client_tls_failed", "target_service": bool(CAPTURE_HOST.fullmatch(host)),
                     "category": tls_failure_category(getattr(data.conn, "error", None))})

    def tls_failed_server(self, data):
        host = data.context.server.address[0] if data.context.server.address else ""
        self.record({"event": "server_tls_failed", "target_service": bool(CAPTURE_HOST.fullmatch(host)),
                     "category": tls_failure_category(getattr(data.conn, "error", None))})

    def error(self, flow):
        self.record({"event": "request_failed"})


def memory_certstore(public_directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from mitmproxy import certs
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FindMy Ledger Temporary Probe")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256()))
    der = certificate.public_bytes(serialization.Encoding.DER)
    (public_directory / "temporary-probe.cer").write_bytes(der)
    # DH parameters and the certificate are public. The RSA key is never serialized.
    dhparams = certs.CertStore.load_dhparam(public_directory / "public-dhparam.pem")
    return certs.CertStore(key, certs.Cert(certificate), None, certs.dummy_crl(key, certificate), dhparams), der


async def run(args):
    from importlib.metadata import version
    from mitmproxy import certs, options
    from mitmproxy.tools.dump import DumpMaster
    if version("mitmproxy") != "12.2.1":
        raise ValueError("Unexpected capture dependency version")
    directory = args.output_dir.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    store, certificate_der = memory_certstore(directory)
    opts = options.Options(listen_host=args.bind, listen_port=args.port, confdir=str(directory),
                           allow_hosts=[r"^(?:(?:p[0-9]{1,3}-)?fmfmobile\.icloud\.com|gateway\.icloud\.com|findmy-ledger\.invalid):443$"],
                           ssl_insecure=False, upstream_cert=False)
    # Prevent the default TLS addon from generating/writing a persistent CA.
    with patch.object(certs.CertStore, "from_store", return_value=store):
        master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        opts.update(body_size_limit="4m", connection_strategy="lazy")
        capture = NativeCapture(master, bind=args.bind, client_ip=args.client_ip, certificate_der=certificate_der,
                                output=directory / "request-shapes.jsonl")
        master.addons.add(capture)
        loop = asyncio.get_running_loop()
        timer = loop.call_later(args.seconds, capture.stop, "deadline")
        print(json.dumps({"stage": "native_request_probe", "bind": args.bind, "port": args.port,
                          "client_ip": args.client_ip, "expires_in_seconds": args.seconds,
                          "certificate_download_path": capture.certificate_path,
                          "https_control_url": f"https://{TLS_CONTROL_HOST}{TLS_CONTROL_PATH}",
                          "raw_traffic_saved": False, "certificate_private_key_saved": False}), flush=True)
        try:
            await master.run()
        finally:
            timer.cancel()
            capture.finish()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True)
    parser.add_argument("--client-ip", required=True)
    parser.add_argument("--port", type=int, default=8877)
    parser.add_argument("--seconds", type=int, choices=range(1, 1201), default=600)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    for field in ("bind", "client_ip"):
        address = ipaddress.IPv4Address(getattr(args, field))
        if not address.is_private or address.is_unspecified:
            parser.error("Use a specific private or loopback address")
        setattr(args, field, str(address))
    logging.disable(logging.CRITICAL)
    try:
        asyncio.run(run(args))
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps({"stage": "native_request_probe", "success": False, "error_type": type(error).__name__}), flush=True)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
