"""Restore the saved Apple session in-process without logging in or printing it."""
from pathlib import Path

from .auth_probe import check_version
from .mac_provider import MacProvider
from .windows_secrets import load


def validate_session(state, identity):
    if state.get("type") != "account" or state.get("anisette", {}).get("type") != "aniMacEmulated":
        raise ValueError("Unsupported session provider")
    if state.get("ids") != {"uid": identity["local_user_uuid"], "devid": identity["device_id"]}:
        raise ValueError("Session belongs to a different emulated machine")
    if state.get("account", {}).get("password") is not None:
        raise ValueError("Session unexpectedly contains a password")
    from findmy import LoginState
    if state.get("login", {}).get("state") != LoginState.LOGGED_IN.value:
        raise ValueError("Saved session is not logged in")
    data = state["login"]["data"]
    if not isinstance(data.get("dsid"), str) or not data["dsid"].isdigit():
        raise ValueError("Saved session has no valid DSID")
    tokens = data.get("mobileme_data", {}).get("tokens", {})
    if not isinstance(tokens.get("mmeFMFAppToken"), str) or not tokens["mmeFMFAppToken"]:
        raise ValueError("Saved session has no Friends token")


def restore(state_dir):
    check_version()
    state_dir = Path(state_dir)
    state = load(state_dir / "apple-session.dpapi")
    provider = MacProvider(state_dir)
    validate_session(state, provider.identity)
    return state, provider
