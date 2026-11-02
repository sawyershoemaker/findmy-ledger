"""Generate short-lived IDS validation in a separate Windows emulator process.

The separately obtained pypush legacy emulator is SSPL-licensed. Its network
and binary-loading functions are replaced here before any operation runs.
"""
import argparse
import base64
import copy
import hashlib
import json
import logging
import plistlib
import secrets
import sys
import time
import urllib.request
from pathlib import Path
from uuid import UUID

from .windows_secrets import load, save_atomic

NAC_SHA256 = "74c2a8fe826a478f14f6e17b3709a8b315e8c0e0e34e3fba6b9c4eee2f4516e9"


def machine_profile(fake_data, identity, encode_value):
    if not identity["client_info"].startswith("<MacBookPro13,2> <macOS;13.1;22C65>"):
        raise ValueError("Unsupported validation machine profile")
    result = copy.deepcopy(fake_data)
    info = result["iokit"]
    info["IOPlatformUUID"] = str(UUID(identity["host_uuid"])).upper()
    info["IOPlatformSerialNumber"] = identity["serial"]
    info["product-name"] = b"MacBookPro13,2\0"
    info["board-id"] = b"Mac-66E35819EE2D0D05\0"
    # Board mapping is from OpenCorePkg's generated Mac model database.
    # These encodings are derived from the plaintext hardware fields. Keeping
    # the template's old values would create two contradictory identities.
    info["Gq3489ugfi"] = encode_value(info["IOPlatformSerialNumber"].encode("ascii"))
    info["Fyp98tpgj"] = encode_value(UUID(info["IOPlatformUUID"]).bytes)
    return result


def generate(state_dir, status):
    from .ids_tls import trust_context
    state_dir = Path(state_dir)
    config = json.loads((state_dir / "push-helper-config.json").read_text(encoding="utf-8-sig"))
    binary = Path(config["nac_binary"]).read_bytes()
    if hashlib.sha256(binary).hexdigest() != NAC_SHA256:
        raise ValueError("Unexpected NAC binary")
    sys.path.insert(0, str(Path(config["nac_source_path"])))
    from pypush.emulated import nac
    from .io_encoder import encode
    identity = load(state_dir / "mac-machine.dpapi")["identity"]
    nac.FAKE_DATA = machine_profile(nac.FAKE_DATA, identity, lambda data: encode(config["io_encoder_binary"], data))
    nac.load_binary = lambda: binary
    nac.arc4random = lambda _: secrets.randbits(32)
    context = trust_context()

    def request_plist(url, body=None):
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/x-apple-plist"})
        with urllib.request.urlopen(req, timeout=25, context=context) as response:
            status["http_status"] = response.status
            return plistlib.loads(response.read())

    def get_cert():
        status["phase"] = "validation_certificate"
        result = request_plist("https://static.ess.apple.com/identity/validation/cert-1.0.plist")["cert"]
        status["phase"] = "validation_emulator_init"
        return result

    def get_session_info(request):
        status["phase"] = "validation_session"
        result = request_plist("https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/initializeValidation",
                               plistlib.dumps({"session-info-request": bytes(request)}))["session-info"]
        status["phase"] = "validation_emulator_sign"
        return result

    nac.get_cert = get_cert
    nac.get_session_info = get_session_info
    validation = bytes(nac.generate_validation_data())
    if not validation or len(validation) > 65536:
        raise ValueError("Unexpected validation blob size")
    save_atomic(state_dir / "nac-validation.dpapi", {"created_at": time.time(), "device_id": identity["device_id"],
                "validation_data": base64.b64encode(validation).decode("ascii"),
                "profile_encoding_version": 2,
                "device_profile": {"product_type": "MacBookPro13,2", "os_version": "13.1", "os_build": "22C65"}})
    return {"stage": "ids_validation", "success": True, "generated_on_windows": True,
            "session_tls_verified": True, "public_certificate_transport": "https",
            "validation_saved_encrypted": True, "bytes": len(validation),
            "ids_registered": False, "live_collection_ready": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    status = {"stage": "ids_validation", "phase": "load_emulator", "http_status": None}
    try:
        result = generate(args.state_dir, status)
        print(json.dumps(result, indent=2))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        status.update({"success": False, "error_type": type(error).__name__, "live_collection_ready": False})
        # Exception text, validation blobs and machine properties are never printed.
        print(json.dumps(status, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
