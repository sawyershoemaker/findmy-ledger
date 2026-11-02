"""A persistent local pause after HTTP 429; contains no account data."""
import json
import time
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_PAUSE_SECONDS = 45 * 60


def utc_text(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds")


def record(state_dir, status, *, now=None):
    if status.get("http_status") != 429:
        return None
    now = time.time() if now is None else now
    server_delay = status.get("retry_after_seconds")
    delay = max(DEFAULT_PAUSE_SECONDS, server_delay if type(server_delay) is int else 0)
    path = Path(state_dir) / "auth-cooldown.json"
    previous_until = 0
    if path.exists():
        previous = json.loads(path.read_text(encoding="utf-8"))
        previous_until = previous["not_before_unix"]
    until = max(previous_until, int(now + delay + 0.999))
    data = {"not_before_unix": until, "retry_not_before_utc": utc_text(until),
            "cause": "http_429", "automatic_retry": False}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data


def active(state_dir, *, now=None):
    now = time.time() if now is None else now
    path = Path(state_dir) / "auth-cooldown.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    until = data["not_before_unix"]
    if type(until) is not int or until < 0:
        raise ValueError("Invalid local cooldown state")
    if now >= until:
        return None
    return {"stage": "auth_probe", "phase": "local_cooldown", "success": False,
            "reason": "retry_cooldown_active", "retry_not_before_utc": utc_text(until),
            "seconds_remaining": int(until - now + 0.999),
            "apple_account_sign_in_attempted": False, "automatic_retry": False,
            "live_collection_ready": False}
