"""Refresh local sign-in and immediately use its short-lived IDS token."""
import argparse
import asyncio
import hashlib
import json
import logging
from pathlib import Path

from .auth_cooldown import active, record
from .auth_diagnostics import AuthTrace
from .auth_probe import provision, check_version
from .ids_probe import register, status_summary, failure_summary
from .io_encoder import ENCODER_SHA256
from .nac_worker import NAC_SHA256
from .windows_secrets import load


def preflight(state_dir):
    from importlib.metadata import version
    check_version()
    if version("pypush") != "2.0.2" or version("unicorn") != "2.1.4":
        raise ValueError("Install the pinned push helper dependencies")
    config = json.loads((state_dir / "push-helper-config.json").read_text(encoding="utf-8-sig"))
    for field, expected in (("nac_binary", NAC_SHA256), ("io_encoder_binary", ENCODER_SHA256)):
        if hashlib.sha256(Path(config[field]).read_bytes()).hexdigest() != expected:
            raise ValueError("Unexpected validation helper binary")
    for name in ("apple-session.dpapi", "mac-machine.dpapi", "apns.dpapi", "selected-person.dpapi"):
        if not (state_dir / name).is_file():
            raise ValueError("Complete account, push, and participant setup first")
    return {"stage": "device_registration_preflight", "success": True, "helper_hashes_verified": True,
            "required_state_present": True, "network_tested": False, "live_collection_ready": False}


async def run(state_dir, trace):
    cooldown = active(state_dir)
    if cooldown:
        return cooldown
    preflight(state_dir)
    ids_path = state_dir / "ids.dpapi"
    if ids_path.exists():
        existing = load(ids_path)
        if existing.get("registered"):
            return status_summary(existing)
    code = await provision(state_dir, trace, refresh_existing=True)
    if code != 0:
        return {"stage": "ids_registration", "success": False, "reason": "sign_in_did_not_finish",
                "automatic_retry": False, "live_collection_ready": False}
    return await register(state_dir, trace)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--doctor", action="store_true")
    args = parser.parse_args()
    trace = AuthTrace()
    logging.disable(logging.CRITICAL)
    try:
        result = preflight(args.state_dir) if args.doctor else asyncio.run(run(args.state_dir, trace))
    except (Exception, KeyboardInterrupt) as error:
        result = failure_summary(trace, error)
        cooldown = record(args.state_dir, result)
        if cooldown:
            result["retry_not_before_utc"] = cooldown["retry_not_before_utc"]
    if not args.doctor:
        (args.state_dir / "ids-status.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result.get("success") else 2


if __name__ == "__main__":
    raise SystemExit(main())
