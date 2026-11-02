"""Obtain one unspent escrow credential locally, without replacing the saved session."""
import argparse
import asyncio
import getpass
import json
import logging
import re
import sys
import time
from pathlib import Path
from types import MethodType

from . import auth_cooldown
from .apple_account import make_account
from .auth_diagnostics import AuthTrace
from .auth_probe import check_version, local_provider
from .saved_session import validate_session
from .windows_secrets import load, save_atomic


async def keep_unspent_pet(self):
    """2FA completion calls this hook; never exchange its PET for service tokens."""
    from findmy import LoginState
    if self.login_state != LoginState.AUTHENTICATED or not self._login_state_data.get("idms_pet"):
        raise ValueError("Authentication did not issue an escrow credential")
    return self.login_state


async def obtain(directory, trace):
    check_version()
    cooldown = auth_cooldown.active(directory)
    if cooldown:
        return cooldown
    if not sys.stdin.isatty():
        raise RuntimeError("Use an interactive local terminal")
    previous = load(directory / "apple-session.dpapi")
    provider = local_provider(directory)
    account = make_account(provider, trace)
    try:
        validate_session(previous, provider.identity)
        selected = load(directory / "selected-person.dpapi")
        if selected.get("account_dsid") != previous["login"]["data"]["dsid"]:
            raise ValueError("Selected participant does not match the account")
        expected_adsid = previous.get("protocol_bootstrap", {}).get("adsid")
        if not expected_adsid:
            raise ValueError("Saved authentication identity is unavailable")
        account._login_mobileme = MethodType(keep_unspent_pet, account)
        print("Unlock the Find My cloud sharing-key backup for the selected participant.")
        print("Using the saved Apple Account and Windows machine identity.")
        print("Your password is not saved. The existing Apple session stays in place.")
        trace.enter("local_input")
        password = getpass.getpass("Apple Account password (hidden): ")
        if not password:
            raise ValueError("Password is required")
        state = await asyncio.wait_for(account.login(previous["account"]["username"], password), 180)
        password = None
        if state.name == "REQUIRE_2FA":
            print("Apple requires two-factor authentication.")
            methods = await asyncio.wait_for(account.get_2fa_methods(), 60)
            for i, method in enumerate(methods, 1):
                print(f"{i}: " + ("Trusted Apple device" if "TrustedDevice" in type(method).__name__ else "SMS"))
            choice = int(input("Choose a 2FA method number: ")) - 1
            if not 0 <= choice < len(methods):
                raise ValueError("Invalid second-factor choice")
            method = methods[choice]
            code = getpass.getpass("If Apple already sent a code, enter it (hidden); otherwise press Enter to request one: ").strip()
            if not code:
                await asyncio.wait_for(method.request(), 60)
                code = getpass.getpass("Six-digit 2FA code (hidden): ").strip()
            if not re.fullmatch(r"[0-9]{6}", code):
                raise ValueError("Expected six digits")
            state = await asyncio.wait_for(method.submit(code), 120)
            code = None
        values = account._login_state_data
        if state.name != "AUTHENTICATED" or values.get("adsid") != expected_adsid or not values.get("idms_pet"):
            raise ValueError("Fresh credential identity could not be verified")
        save_atomic(directory / "keychain-pet.dpapi", {"account_dsid": previous["login"]["data"]["dsid"],
            "device_id": provider.account_ids["devid"], "adsid": expected_adsid,
            "pet": values["idms_pet"], "created_at": time.time()})
        return {"stage": "local_keychain_authentication", "success": True, "password_saved": False,
                "existing_session_replaced": False, "automatic_retry": False, "live_collection_ready": False}
    finally:
        password = None
        account._password = None
        await account.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--doctor", action="store_true")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    trace = AuthTrace()
    result = {}
    try:
        if args.doctor:
            check_version()
            result = {"stage": "keychain_auth_preflight", "success": True, "account_requests": 0}
        else:
            result = asyncio.run(obtain(args.state_dir.resolve(), trace))
    except (Exception, KeyboardInterrupt) as error:
        result = trace.failure(error)
        result["stage"] = "local_keychain_authentication"
        cooldown = auth_cooldown.record(args.state_dir, result)
        if cooldown:
            result.update(cooldown)
    if not args.doctor:
        (args.state_dir / "keychain-auth-status.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result.get("success") else 2


if __name__ == "__main__":
    raise SystemExit(main())
