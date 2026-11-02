from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from . import store
from . import maintenance
from .profile import weekly_profile


def main():
    parser = argparse.ArgumentParser(description="Local Find My Ledger history, reports, and maintenance")
    parser.add_argument("--db", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    reg = sub.add_parser("register")
    reg.add_argument("participant")
    # Accept the obsolete switch silently so existing scripts keep working.
    reg.add_argument("--consent-to-history-and-analysis", action="store_true", help=argparse.SUPPRESS)
    pause = sub.add_parser("pause")
    pause.add_argument("participant")
    resume = sub.add_parser("resume")
    resume.add_argument("participant")
    resume.add_argument("--consent-to-history-and-analysis", action="store_true", help=argparse.SUPPRESS)
    backup = sub.add_parser("backup", help="Create a consistent snapshot at a new path")
    backup.add_argument("destination", type=Path)
    restore = sub.add_parser("restore", help="Restore a snapshot to the new --db path")
    restore.add_argument("snapshot", type=Path)
    retain = sub.add_parser("retain", help="Preview or apply a participant's retention cutoff")
    retain.add_argument("participant")
    retain.add_argument("--before", required=True)
    retain.add_argument("--apply", action="store_true")
    forget = sub.add_parser("forget", help="Preview or delete history and places, and pause collection")
    forget.add_argument("participant")
    forget.add_argument("--apply", action="store_true")
    sub.add_parser("compact", help="Reclaim unused pages after deletion; close other readers first")
    optimize = sub.add_parser('optimize', help='Preview or backup and coalesce stationary history; stop collector before --apply')
    optimize.add_argument('participant')
    optimize.add_argument('--radius-m', type=float, default=25)
    optimize.add_argument('--max-gap', type=int, default=600)
    optimize.add_argument('--apply', action='store_true')
    optimize.add_argument('--backup', type=Path)
    imp = sub.add_parser("import")
    imp.add_argument("participant")
    imp.add_argument("jsonl", type=Path)
    imp.add_argument("--adaptive", action="store_true", help="Keep movement changes and periodic stationary samples")
    imp.add_argument("--movement-m", type=float, default=10)
    imp.add_argument("--stationary-seconds", type=int, default=300)
    place = sub.add_parser("place")
    place.add_argument("participant")
    place.add_argument("label")
    place.add_argument("latitude", type=float)
    place.add_argument("longitude", type=float)
    place.add_argument("--radius", type=float, default=100)
    query = sub.add_parser("report")
    query.add_argument("participant")
    query.add_argument("--start", required=True)
    query.add_argument("--end", required=True)
    query.add_argument("--max-gap", type=int, default=600)
    profile = sub.add_parser("profile")
    profile.add_argument("participant")
    profile.add_argument("--start", required=True)
    profile.add_argument("--end", required=True)
    profile.add_argument("--timezone", required=True)
    analysis = sub.add_parser("analyze", help="Named timeline and recurring observations; free cached geocoding when enabled")
    analysis.add_argument("participant")
    analysis.add_argument("--start", required=True)
    analysis.add_argument("--end", required=True)
    analysis.add_argument("--timezone", required=True)
    analysis.add_argument("--offline", action="store_true", help="Use existing place names without network requests")
    analysis.add_argument("--max-gap", type=int, default=600)
    analysis.add_argument("--min-stop-seconds", type=int, default=120)
    geocoding = sub.add_parser("geocoding", help="Show or configure free Photon lookups for a participant")
    geocoding.add_argument("participant")
    mode = geocoding.add_mutually_exclusive_group()
    mode.add_argument("--enable-free-online", action="store_true")
    mode.add_argument("--disable-online", action="store_true")
    sub.add_parser("stats")
    sub.add_parser("demo")
    args = parser.parse_args()
    try:
        if args.command == 'analyze':
            from .analysis import analyze
            print(json.dumps(analyze(args.db, args.participant, args.start, args.end,
                timezone_name=args.timezone, offline=args.offline, max_gap=args.max_gap,
                min_stop_seconds=args.min_stop_seconds), indent=2))
            return
        if args.command == 'geocoding':
            from .geocoding import PlaceCache, cache_path
            with store.connect(args.db) as db:
                store.subject(db, args.participant, require_active=args.enable_free_online)
            enabled = True if args.enable_free_online else False if args.disable_online else None
            print(json.dumps(PlaceCache(cache_path(args.db)).configure(args.participant, enabled), indent=2))
            return
        if args.command == 'optimize':
            from .history import StayPolicy
            result = maintenance.optimize(args.db, args.participant,
                policy=StayPolicy(radius_m=args.radius_m, gap_seconds=args.max_gap),
                apply=args.apply, backup_path=args.backup)
            print(json.dumps(result, indent=2))
            return
        if args.command in ("backup", "restore", "compact"):
            result = (maintenance.backup(args.db, args.destination) if args.command == "backup"
                      else maintenance.backup(args.snapshot, args.db) if args.command == "restore"
                      else maintenance.compact(args.db))
            if args.command == "restore":
                result["restored_to"] = result.pop("backup_created")
            print(json.dumps(result, indent=2))
            return
        if args.command in ("init", "demo"):
            store.initialize(args.db)
            if args.command == "init":
                print(json.dumps({"created": str(args.db)}))
                return
        write = args.command not in ("report", "profile", "stats")
        if args.command in ("retain", "forget") and not args.apply:
            write = False
        with store.connect(args.db, write=write) as db:
            if args.command == "register":
                store.register(db, args.participant)
                result = {"registered": args.participant}
            elif args.command == "pause":
                sid = store.subject(db, args.participant)["id"]
                db.execute("UPDATE subjects SET active=0 WHERE id=?", (sid,))
                result = {"paused": args.participant}
            elif args.command == "resume":
                sid = store.subject(db, args.participant)["id"]
                db.execute("UPDATE subjects SET active=1,consent_at=strftime('%s','now') WHERE id=?", (sid,))
                result = {"resumed": args.participant}
            elif args.command == "retain":
                result = maintenance.retain(db, args.participant, args.before, apply=args.apply)
            elif args.command == "forget":
                result = maintenance.forget(db, args.participant, apply=args.apply)
            elif args.command == "import":
                inserted, duplicates = 0, 0
                coalesced = 0
                sampler = None
                if args.adaptive:
                    from .sampling import AdaptiveSampler, SamplingPolicy, write_decision
                    sampler = AdaptiveSampler.from_database(db, args.participant,
                        SamplingPolicy(movement_m=args.movement_m, stationary_seconds=args.stationary_seconds))
                with args.jsonl.open(encoding="utf-8-sig") as stream:
                    for index, line in enumerate(stream, 1):
                        if not line.strip():
                            continue
                        try:
                            if sampler is None:
                                added = store.ingest(db, args.participant, json.loads(line))
                                inserted += added
                                duplicates += not added
                            else:
                                outcome = write_decision(db, args.participant, sampler.accept(json.loads(line)))
                                inserted += outcome["inserted"]
                                duplicates += outcome["duplicates"]
                                coalesced += outcome["coalesced"]
                        except (ValueError, KeyError, TypeError) as error:
                            raise ValueError(f"Import failed at line {index}; transaction rolled back: {error}") from error
                if sampler is not None:
                    outcome = write_decision(db, args.participant, sampler.flush())
                    inserted += outcome["inserted"]
                    duplicates += outcome["duplicates"]
                result = {"inserted": inserted, "duplicates": duplicates}
                if sampler is not None:
                    result.update(coalesced_updates=coalesced, adaptive_sampling=True,
                                  movement_m=args.movement_m, stationary_seconds=args.stationary_seconds)
            elif args.command == "place":
                store.add_place(db, args.participant, args.label, args.latitude, args.longitude, args.radius)
                result = {"place": args.label}
            elif args.command == "report":
                result = store.report(db, args.participant, args.start, args.end, max_gap=args.max_gap)
            elif args.command == "stats":
                result = store.statistics(db)
            elif args.command == "profile":
                result = weekly_profile(db, args.participant, args.start, args.end, timezone_name=args.timezone)
            elif args.command == "demo":
                store.register(db, "synthetic-participant")
                store.add_place(db, "synthetic-participant", "Demo A", 40.0, -75.0, 100)
                store.add_place(db, "synthetic-participant", "Demo B", 40.02, -75.03, 100)
                base = store.epoch("2026-10-19T00:00:00Z")
                for minute in range(0, 24 * 60, 5):
                    if 720 <= minute < 780:  # Deliberate data gap.
                        continue
                    at_a = minute < 540 or minute >= 1020
                    store.ingest(db, "synthetic-participant", {
                        "observed_at": base + minute * 60, "latitude": 40.0 if at_a else 40.02,
                        "longitude": -75.0 if at_a else -75.03, "accuracy_m": 12, "source": "synthetic"
                    }, received_at=base + minute * 60 + 3)
                result = store.report(db, "synthetic-participant", base, base + 86400)
                result["synthetic"] = True
        if args.command == 'forget' and args.apply:
            from .geocoding import PlaceCache, cache_path
            path = cache_path(args.db)
            result['cached_areas_deleted'] = PlaceCache(path).forget(args.participant) if path.exists() else 0
            result['online_geocoding_disabled'] = True
        print(json.dumps(result, indent=2))
    except (ValueError, KeyError, TypeError, OSError, sqlite3.Error) as error:
        parser.exit(2, f"Error: {error}\n")


if __name__ == "__main__":
    main()
