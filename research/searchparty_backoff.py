"""Persist SearchParty's Retry-After without retrying or changing login state."""
import json
import math
import os
import tempfile
import time
from pathlib import Path

from .auth_cooldown import utc_text


def record(state_dir, status, *, now=None):
    code, delay = status.get("http_status"), status.get("retry_after_seconds")
    if code not in (429, 503) or type(delay) is not int or not 0 <= delay < 2 ** 31:
        return None
    now = time.time() if now is None else now
    directory = Path(state_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "searchparty-backoff.json"
    until = math.ceil(now + delay)
    if path.exists():
        until = max(until, _deadline(path))
    result = {"not_before_unix": until, "retry_not_before_utc": utc_text(until),
              "http_status": code, "automatic_retry": False}
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=directory, delete=False) as output:
        temporary = Path(output.name)
        json.dump(result, output, indent=2)
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return result


def _deadline(path):
    value = json.loads(path.read_text(encoding="utf-8"))["not_before_unix"]
    if type(value) is not int or not 0 <= value < 2 ** 53:
        raise ValueError("Invalid SearchParty backoff")
    return value


def active(state_dir, *, now=None, ignore_503=False):
    now = time.time() if now is None else now
    path = Path(state_dir) / "searchparty-backoff.json"
    if not path.exists():
        return None
    until = _deadline(path)
    if ignore_503 and json.loads(path.read_text(encoding="utf-8")).get("http_status") == 503:
        return None
    if now >= until:
        return None
    return {"stage": "searchparty_backoff", "success": False, "reason": "server_retry_after_active",
            "retry_not_before_utc": utc_text(until), "seconds_remaining": math.ceil(until - now),
            "network_request_attempted": False, "automatic_retry": False, "live_collection_ready": False}


class SearchPartyError(Exception):
    """A service/protocol failure whose message never includes an Apple body."""


async def read_limited(content, limit):
    """Read through EOF, including fragmented/chunked bodies, with a hard cap."""
    result = bytearray()
    async for chunk in content.iter_chunked(64 * 1024):
        if len(result) + len(chunk) > limit:
            raise SearchPartyError("SearchParty response exceeds the probe limit")
        result.extend(chunk)
    return bytes(result)

