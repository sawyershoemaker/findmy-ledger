"""Test the emulated machine's initial Apple challenge with a reserved invalid account."""
import argparse
import asyncio
import json
import logging
from pathlib import Path

from .apple_account import make_account
from .auth_diagnostics import AuthTrace
from .auth_probe import check_version


async def preflight(state_dir):
    from findmy.reports.account import srp
    from .mac_provider import MacProvider
    check_version()
    trace = AuthTrace()
    account = make_account(MacProvider(state_dir), trace)
    try:
        username = "findmy-ledger-probe@example.invalid"
        user = srp.User(username, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        _, public_value = user.start_authentication()
        await account._gsa_request({"A2k": public_value, "u": username, "ps": ["s2k", "s2k_fo"], "o": "init"})
        return {"stage": "emulated_mac_preflight", "credential_free": True,
                "real_account_sign_in_attempted": False, "http_status": trace.http_status,
                "apple_status": trace.apple_status, "apple_http_status": trace.apple_http_status,
                "machine_accepted_for_initial_challenge": trace.apple_status in (0, -20970),
                "live_collection_ready": False}
    except Exception as error:
        return trace.failure(error)
    finally:
        await account.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    print(json.dumps(asyncio.run(preflight(args.state_dir)), indent=2))
