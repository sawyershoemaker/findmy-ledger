"""FindMy.py provider for the local Windows worker; no remote anisette service."""
import asyncio
import base64
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

from findmy.reports.anisette import BaseAnisetteProvider

from .windows_secrets import load, transform

_HEADER_WORKER_LOCK = threading.Lock()


class MacProvider(BaseAnisetteProvider):
    def __init__(self, state_dir):
        super().__init__()
        self.state_dir = Path(state_dir).resolve()
        self.config_path = self.state_dir / "mac-helper-config.json"
        self.identity = load(self.state_dir / "mac-machine.dpapi")["identity"]
        self.account_ids = {"uid": self.identity["local_user_uuid"], "devid": self.identity["device_id"]}
        self._headers = None
        self._window = None

    @property
    def client(self):
        return self.identity["client_info"]

    @property
    def mobileme_client(self):
        return self.client.split(" <com.apple.", 1)[0] + " <com.apple.AOSKit/282 (com.apple.accountsd/113)>"

    @property
    def otp(self):
        return (self._headers or {}).get("X-Apple-I-MD", "")

    @property
    def machine(self):
        return (self._headers or {}).get("X-Apple-I-MD-M", "")

    def _read_headers(self, *, force_refresh=False):
        # Polling and push-key refresh can start together. Serialize their local
        # ADI workers so they cannot contend for the same encrypted machine state.
        with _HEADER_WORKER_LOCK:
            return self._read_headers_locked(force_refresh=force_refresh)

    def _read_headers_locked(self, *, force_refresh=False):
        window = int(time.time()) // 30
        if force_refresh or self._headers is None or window != self._window:
            result = subprocess.run(
                [sys.executable, "-m", "research.mac_helper", "headers-internal", "--config", str(self.config_path),
                 "--state-dir", str(self.state_dir)],
                cwd=Path(__file__).resolve().parent.parent, capture_output=True, text=True,
                timeout=180, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if result.returncode != 0:
                raise RuntimeError("The local Mac authentication worker failed")
            message = json.loads(result.stdout)
            payload = json.loads(transform(base64.b64decode(message["protected_headers"], validate=True), decrypt=True))
            if payload["identity"] != self.identity:
                raise ValueError("The worker's machine identity changed")
            self._headers = payload["headers"]
            self._window = window
        return dict(self._headers)

    async def get_headers(self, user_id, device_id, serial="0", with_client_info=False, *, force_refresh=False):
        if user_id != self.account_ids["uid"] or device_id != self.account_ids["devid"]:
            raise ValueError("The account and authentication worker must use the same identity")
        headers = await asyncio.to_thread(self._read_headers, force_refresh=force_refresh)
        headers.pop("X-MMe-Client-Info", None)
        headers["loc"] = headers["X-Apple-Locale"]
        if with_client_info:
            headers.update({"X-Mme-Client-Info": self.client,
                            "X-Apple-App-Info": "com.apple.gs.xcode.auth", "X-Xcode-Version": "11.2 (11B41)"})
        return headers

    def to_json(self, dst=None):
        if dst is not None:
            raise ValueError("Store the account through the protected session writer")
        return {"type": "aniMacEmulated", "state_dir": str(self.state_dir)}

    @classmethod
    def from_json(cls, mapping):
        if mapping.get("type") != "aniMacEmulated":
            raise ValueError("Unexpected provider mapping")
        return cls(mapping["state_dir"])

    async def close(self):
        self._headers = None
        self._window = None
