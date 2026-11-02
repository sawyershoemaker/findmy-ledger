"""Discover shared-person relationships and select a participant locally."""
import argparse
import asyncio
import json
import logging
import sys
import time
from pathlib import Path

from .auth_cooldown import active, record
from .auth_diagnostics import AuthTrace
from .fmf_client import FriendsClient, FriendsError, following, relationship_shape
from .saved_session import restore
from .windows_secrets import load, save_atomic, save_new


async def discover(state_dir, trace):
    state, provider = restore(state_dir)
    client = FriendsClient(state, provider, trace)
    try:
        response = await client.request()
        rows = following(response)
        save_atomic(state_dir / "people-list.dpapi", {"created_at": time.time(), "account_dsid": state["login"]["data"]["dsid"],
                                                     "relationships": rows})
        result = {"stage": "people_discovery", "success": True, "session_restored": True,
                  "accepted_relationships": len(rows),
                  "secure_relationships": sum(row["secure_locations_capable"] is True for row in rows),
                  "legacy_fallback_relationships": sum(row["legacy_fallback_allowed"] is True for row in rows),
                  "response_shape": relationship_shape(response),
                  "people_key_received": False, "live_collection_ready": False}
        (state_dir / "people-status.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result
    finally:
        await client.close()


def select_person(state_dir):
    destination = state_dir / "selected-person.dpapi"
    if destination.exists():
        return {"stage": "participant_selection", "participant_selected": True, "already_selected": True,
                "people_key_received": False, "live_collection_ready": False}
    if not sys.stdin.isatty():
        raise ValueError("Participant selection requires an interactive local terminal")
    cached = load(state_dir / "people-list.dpapi")
    rows = cached["relationships"]
    if time.time() - cached["created_at"] > 3600:
        raise FriendsError("relationship_list_needs_refresh")
    if not rows:
        raise FriendsError("no_accepted_relationships")
    print("Choose the participant to record. Names/handles stay in this terminal.")
    for index, row in enumerate(rows, 1):
        print(f"{index}: " + ", ".join("".join(c for c in h if c.isprintable()) for h in row["handles"]))
    index = int(input("Participant number: ")) - 1
    if not 0 <= index < len(rows):
        raise ValueError("Participant selection is out of range")
    row = rows[index]
    save_new(destination, {"account_dsid": cached["account_dsid"], "relationship": row,
                           "alias": "participant", "selected_at": time.time()})
    result = {"stage": "participant_selection", "participant_selected": True,
              "secure_locations_capable": row["secure_locations_capable"],
              "legacy_fallback_allowed": row["legacy_fallback_allowed"],
              "people_key_received": False, "live_collection_ready": False}
    (state_dir / "participant-status.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["discover", "select"])
    parser.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    trace = AuthTrace()
    try:
        if args.command == "discover":
            cooldown = active(args.state_dir)
            if cooldown:
                print(json.dumps(cooldown, indent=2))
                return 2
            result = asyncio.run(discover(args.state_dir, trace))
        else:
            result = select_person(args.state_dir)
        print(json.dumps(result, indent=2))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        status = trace.failure(error)
        status.update({"stage": "people_discovery" if args.command == "discover" else "participant_selection",
                       "phase": "friends_init" if args.command == "discover" else "local_selection"})
        if isinstance(error, FriendsError):
            status["reason"] = error.category
        cooldown = record(args.state_dir, status)
        if cooldown:
            status["retry_not_before_utc"] = cooldown["retry_not_before_utc"]
        (args.state_dir / "people-status.json").write_text(json.dumps(status, indent=2), encoding="utf-8")
        print(json.dumps(status, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
