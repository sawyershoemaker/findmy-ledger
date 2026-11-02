"""Windows worker around the separately installed GPL-2.0 macOS ADI emulator.

No Apple binaries or upstream source are bundled in this project. Private state
and the internal header response are protected with current-user Windows DPAPI.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from .extract_coreadi import EXPECTED_SHA256
from .windows_secrets import load, save_atomic, transform

UPSTREAM_COMMIT = "d4d2a832baf47d1cf43d989879950ac2aec45f47"


@contextmanager
def machine_lock(state_dir):
    import msvcrt
    state_dir.mkdir(parents=True, exist_ok=True)
    with (state_dir / "mac-machine.lock").open("a+b") as stream:
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        try:
            yield
        finally:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


def engine(config_path, state_dir):
    config = json.loads(Path(config_path).read_text(encoding="utf-8-sig"))
    binary = Path(config["coreadi_binary"]).resolve()
    upstream = Path(config["upstream_path"]).resolve()
    if config.get("upstream_commit") != UPSTREAM_COMMIT:
        raise ValueError("Unsupported emulator revision")
    if hashlib.sha256(binary.read_bytes()).hexdigest() != EXPECTED_SHA256:
        raise ValueError("Unexpected CoreADI binary")
    os.environ["COREADI_PATH"] = str(binary)
    # OTP must follow real time. A frozen emulator clock invalidates later requests.
    os.environ.pop("ADI_FROZEN_TIME", None)
    sys.path.insert(0, str(upstream / "tools" / "machoadi"))
    from mac_anisette import MacAnisette, STORE_DIR, _mint_identity
    from gsa import GSA, Device
    from findmy.util.tls import apple_trust_context

    class VerifiedGSA(GSA):
        def __init__(self, device):
            super().__init__(device)
            self._ctx = apple_trust_context()

        def _open(self, url, body, *, client_time):
            target = urlsplit(url)
            host = target.hostname or ""
            if (target.scheme != "https" or target.username or target.password or target.port not in (None, 443)
                    or not (host == "apple.com" or host.endswith(".apple.com"))):
                raise ValueError("Unexpected provisioning destination")
            return super()._open(url, body, client_time=client_time)

    class ProtectedMachine(MacAnisette):
        def __init__(self):
            self.secret_path = Path(state_dir) / "mac-machine.dpapi"
            self.saved = load(self.secret_path) if self.secret_path.exists() else {}
            super().__init__(Path(state_dir), log=False)

        def _load_identity(self):
            return self.saved.get("identity") or _mint_identity()

        def _load_store(self):
            for name, encoded in self.saved.get("store", {}).items():
                if name in ("", ".", "..") or len(name) > 255 or any(c in name for c in ("/", "\\", ":", "\0")):
                    raise ValueError("Unexpected virtual machine-state filename")
                if name != "adi.pb":
                    self.adi.stubs.files[f"{STORE_DIR}/{name}"] = bytearray(base64.b64decode(encoded, validate=True))

        def _save_identity(self):
            pass  # Identity and virtual files are committed together by _save_store.

        def _save_store(self):
            store = {name.rsplit("/", 1)[1]: base64.b64encode(bytes(data)).decode("ascii")
                     for name, data in self.adi.stubs.files.items() if name.startswith(STORE_DIR + "/")}
            save_atomic(self.secret_path, {"identity": self.identity, "store": store})

        def provision_verified(self):
            if self.is_provisioned():
                return
            identity = self.identity
            transport = VerifiedGSA(Device(identity["device_id"], identity["client_info"],
                                           identity["local_user_uuid"], identity["serial"]))
            self.provision(transport)

    return ProtectedMachine()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "headers-internal"])
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    try:
        with machine_lock(args.state_dir):
            machine = engine(args.config, args.state_dir)
            if args.command == "prepare":
                machine.provision_verified()
                headers = machine.headers()
                print(json.dumps({"success": True, "stage": "emulated_mac_anisette",
                                  "machine_provisioned": machine.is_provisioned(),
                                  "headers_generated": bool(headers.get("X-Apple-I-MD") and headers.get("X-Apple-I-MD-M")),
                                  "tls_certificate_verified": True, "account_sign_in_attempted": False}))
            else:
                headers = machine.headers()
                blob = transform(json.dumps({"headers": headers, "identity": machine.identity}).encode())
                print(json.dumps({"protected_headers": base64.b64encode(blob).decode("ascii")}))
        return 0
    except (Exception, SystemExit) as error:
        # Never print upstream errors: they may embed a complete Apple response.
        print(json.dumps({"success": False, "stage": "emulated_mac_anisette", "error_type": type(error).__name__}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
