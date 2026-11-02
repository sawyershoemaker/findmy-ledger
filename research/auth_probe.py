"""One interactive Apple sign-in test on Windows. Does not collect locations.

Credentials are typed into a local terminal, never command-line arguments.
FindMy.py performs Apple authentication and provisions anisette locally.
The helper's initial library download is described in the project README.
"""
from __future__ import annotations

import argparse
import asyncio
import copy
import getpass
import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from uuid import uuid4

from .windows_secrets import load, save_new, save_atomic
from .auth_diagnostics import AuthTrace
from .apple_account import make_account
from . import auth_cooldown


def check_version():
    from importlib.metadata import version
    if version("findmy") != "0.10.2":
        raise RuntimeError("Install the pinned FindMy.py 0.10.2 dependency")


def local_provider(state_dir):
    if (state_dir / "mac-helper-config.json").exists():
        from .mac_provider import MacProvider
        return MacProvider(state_dir)
    from findmy import LocalAnisetteProvider
    cache = state_dir / "anisette.dpapi"
    libs = state_dir / "anisette-libs.tar"
    if cache.exists():
        return LocalAnisetteProvider.from_json(load(cache), libs_path=libs)
    return LocalAnisetteProvider(libs_path=libs)


async def prepare(state_dir):
    """Check local emulation and Apple provisioning without signing in."""
    check_version()
    state_dir.mkdir(parents=True, exist_ok=True)
    provider = local_provider(state_dir)
    try:
        ids = getattr(provider, "account_ids", {"uid": str(uuid4()), "devid": str(uuid4())})
        headers = await asyncio.wait_for(provider.get_headers(ids["uid"], ids["devid"]), timeout=180)
        if not all(headers.get(key) for key in ("X-Apple-I-MD", "X-Apple-I-MD-M")):
            raise RuntimeError("Anisette provisioning returned empty headers")
        cache = state_dir / "anisette.dpapi"
        if not hasattr(provider, "account_ids") and not cache.exists():
            save_new(cache, provider.to_json())
        return {"stage": "emulated_mac_anisette" if hasattr(provider, "account_ids") else "local_anisette", "success": True, "windows": True,
                "apple_account_sign_in_attempted": False, "live_collection_ready": False}
    finally:
        await provider.close()


def remove_password(state):
    result = copy.deepcopy(state)
    result["account"]["password"] = None
    return result


def summary(state):
    data = state.get("login", {}).get("data", {})
    tokens = data.get("mobileme_data", {}).get("tokens", {})
    return {"stage": "Apple account authentication only",
            "session_saved": True, "password_saved": False,
            "has_searchparty_token": bool(tokens.get("searchPartyToken")),
            "has_friends_token": bool(tokens.get("mmeFMFAppToken")),
            "has_ids_bootstrap_material": bool(state.get("protocol_bootstrap", {}).get("idms_pet")),
            "people_key_received": False, "live_collection_ready": False}


def save_refreshed_session(path, snapshot, previous):
    old_dsid = previous.get("login", {}).get("data", {}).get("dsid")
    new_dsid = snapshot.get("login", {}).get("data", {}).get("dsid")
    if not old_dsid or old_dsid != new_dsid or previous.get("ids") != snapshot.get("ids"):
        raise ValueError("Refreshed sign-in belongs to a different account or machine")
    if snapshot.get("account", {}).get("password") is not None:
        raise ValueError("A saved session must not contain a password")
    save_atomic(path, snapshot)


async def provision(state_dir, trace, *, refresh_existing=False):
    check_version()
    path = state_dir / "apple-session.dpapi"
    if path.exists() and not refresh_existing:
        print("A saved session exists; no new login was attempted.")
        print(json.dumps(summary(load(path)), indent=2))
        return 0
    cooldown = auth_cooldown.active(state_dir)
    if cooldown:
        print(json.dumps(cooldown, indent=2))
        return 2
    previous = load(path) if refresh_existing else None
    if not sys.stdin.isatty():
        raise RuntimeError("Run login from an interactive local terminal")
    state_dir.mkdir(parents=True, exist_ok=True)
    print("Refresh sign-in, then immediately register the Find My device." if refresh_existing
          else "This tests sign-in only. Find My People collection is not implemented yet.")
    print("Authentication uses the local emulated Mac helper." if (state_dir / "mac-helper-config.json").exists()
          else "The local anisette helper may download its runtime libraries on first use.")
    print("The saved session is encrypted for this Windows user. Your password is not saved.")
    trace.enter("local_input")
    username = previous["account"]["username"] if refresh_existing else input("Apple Account email (local input): ").strip()
    if refresh_existing:
        print("Using the same saved Apple Account and machine identity.")
    password = getpass.getpass("Apple Account password (hidden): ")
    if not username or not password:
        raise ValueError("Both account fields are required")
    account = make_account(local_provider(state_dir), trace)
    try:
        print("Signing in to Apple; this can take a minute...", flush=True)
        trace.enter("account_login")
        state = await asyncio.wait_for(account.login(username, password), timeout=180)
        password = None
        if state.name == "REQUIRE_2FA":
            print("Apple requires two-factor authentication.", flush=True)
            trace.enter("two_factor_methods")
            methods = await asyncio.wait_for(account.get_2fa_methods(), timeout=60)
            if not methods:
                raise RuntimeError("No supported second factor")
            for index, method in enumerate(methods, 1):
                label = "Trusted Apple device" if "TrustedDevice" in type(method).__name__ else "SMS"
                print(f"{index}: {label}")
            choice = int(input("Choose a 2FA method number: ")) - 1
            if choice < 0 or choice >= len(methods):
                raise ValueError("Invalid second-factor choice")
            method = methods[choice]
            trace.enter("two_factor_input")
            code = getpass.getpass("If Apple already sent a code, enter it (hidden); otherwise press Enter to request one: ").strip()
            if not code:
                trace.enter("two_factor_request")
                await asyncio.wait_for(method.request(), timeout=60)
                trace.enter("two_factor_input")
                code = getpass.getpass("Six-digit 2FA code (hidden): ").strip()
            if not re.fullmatch(r"[0-9]{6}", code):
                raise ValueError("Expected six digits")
            trace.enter("two_factor_submit")
            state = await asyncio.wait_for(method.submit(code), timeout=120)
            code = None
        if state.name != "LOGGED_IN":
            raise RuntimeError("Apple sign-in did not reach the logged-in state")
        trace.enter("save_session")
        snapshot = remove_password(account.to_json())
        snapshot["protocol_bootstrap"] = account.bootstrap or {}
        snapshot["protocol_bootstrap"]["saved_at"] = time.time()
        if refresh_existing:
            save_refreshed_session(path, snapshot, previous)
        else:
            save_new(path, snapshot)
        status = summary(snapshot)
        (state_dir / "auth-status.json").write_text(json.dumps(status, indent=2), encoding="utf-8")
        print(json.dumps(status, indent=2))
        return 0
    finally:
        password = None
        await account.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["doctor", "prepare", "login", "status"])
    parser.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()
    trace = AuthTrace()
    # Suppress library loggers: upstream debug logs can contain protocol state.
    logging.disable(logging.CRITICAL)
    try:
        if os.name != "nt":
            raise RuntimeError("This probe is prepared for Windows")
        if args.command == "doctor":
            from importlib.metadata import version
            from findmy import AsyncAppleAccount, LocalAnisetteProvider
            check_version()
            print(json.dumps({"windows": True, "findmy_version": version("findmy"),
                              "imports_ok": True, "network_tested": False,
                              "live_collection_ready": False}, indent=2))
        elif args.command == "prepare":
            trace.enter("prepare")
            print(json.dumps(asyncio.run(prepare(args.state_dir)), indent=2))
        elif args.command == "status":
            trace.enter("status")
            print(json.dumps(summary(load(args.state_dir / "apple-session.dpapi")), indent=2))
        else:
            return asyncio.run(provision(args.state_dir, trace))
    except (Exception, KeyboardInterrupt) as error:
        # Deliberately omit exception text and traceback, which may contain secrets.
        status = trace.failure(error)
        if args.command == "login":
            try:
                args.state_dir.mkdir(parents=True, exist_ok=True)
                cooldown = auth_cooldown.record(args.state_dir, status)
                if cooldown:
                    status["retry_not_before_utc"] = cooldown["retry_not_before_utc"]
                (args.state_dir / "auth-status.json").write_text(json.dumps(status, indent=2), encoding="utf-8")
            except (OSError, ValueError, KeyError, TypeError):
                pass  # Still print the diagnosis if its local file cannot be written.
        print(json.dumps(status, indent=2), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
