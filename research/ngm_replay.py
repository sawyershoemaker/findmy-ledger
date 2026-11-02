"""Durably reserve per-identity outgoing NGM replay counters before sending.

Apple's NGM inner protobuf requires field 2 (uint32), including the first zero.
The stream is scoped by local signing key, peer signing key, and peer prekey.
Gaps are safe; reusing a counter after a process restart is not.
"""
import hashlib
from pathlib import Path

from .collector import collector_lock
from .windows_secrets import load, save_atomic


def reserve_counter(path, sender_public, recipient_public, recipient_prekey):
    keys = (sender_public, recipient_public, recipient_prekey)
    if any(type(key) is not bytes or len(key) != 32 for key in keys):
        raise ValueError("Invalid replay-counter identity")
    identity = hashlib.sha256(b"FindMyLedger-NGM-counter-v1" + b"".join(keys)).hexdigest()
    path = Path(path)
    with collector_lock(path.with_suffix(".lock")):
        state = load(path) if path.exists() else {"version": 1, "next": {}}
        if state.get("version") != 1 or not isinstance(state.get("next"), dict):
            raise ValueError("Invalid replay-counter store")
        counters = state["next"]
        counter = counters.get(identity, 0)
        if type(counter) is not int or not 0 <= counter < 0xffffffff:
            raise ValueError("Replay counter exhausted or invalid")
        if identity not in counters and len(counters) >= 4096:
            raise ValueError("Replay-counter identity limit reached")
        counters[identity] = counter + 1
        save_atomic(path, state)
        return counter
