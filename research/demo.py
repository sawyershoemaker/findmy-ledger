"""Build a deterministic, offline four-week history using only fictional data."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta
import json
from pathlib import Path
from zoneinfo import ZoneInfo

from location_ledger import maintenance, store
from location_ledger.analysis import analyze

ALIAS = "synthetic-participant"
ZONE = "America/New_York"
START = "2026-09-07T00:00:00-04:00"
END = "2026-10-05T00:00:00-04:00"
DAY_START = "2026-09-21T08:00:00-04:00"
DAY_END = "2026-09-21T18:00:00-04:00"
# Arbitrary coordinates and invented labels, unrelated to a real participant.
PLACES = {
    "Maple Corner": (40.00, -75.00),
    "Alder Studio": (40.02, -75.03),
    "Harbor Library": (40.03, -75.01),
    "Juniper Park": (40.01, -75.04),
}


def observations():
    start = datetime.fromisoformat(START)
    for day_index in range(28):
        day = start + timedelta(days=day_index)
        if day.date().isoformat() == "2026-09-19":
            continue  # One entire missing date, never counted as an absence.
        for minute in range(24 * 60):
            if minute % 5:
                continue
            hour = minute // 60
            if day.weekday() < 5:
                if not 8 <= hour < 18:
                    continue
                if day_index == 14 and 12 * 60 + 15 <= minute < 13 * 60:
                    continue  # 50 minutes between the last and next source fix.
                label = ("Maple Corner" if hour == 8 else
                         "Harbor Library" if hour == 12 else
                         "Juniper Park" if hour == 17 and day.weekday() in (0, 2, 4) else
                         "Maple Corner" if hour == 17 else "Alder Studio")
            else:
                if 10 <= hour < 13:
                    label = "Juniper Park"
                elif 14 <= hour < 16:
                    label = "Harbor Library"
                else:
                    continue
            lat, lon = PLACES[label]
            jitter = ((minute * 7 + day_index * 11) % 13 - 6) / 111195
            observed_at = int((day + timedelta(minutes=minute)).timestamp())
            yield {"observed_at": observed_at, "latitude": lat + jitter,
                   "longitude": lon, "accuracy_m": 8, "source": "synthetic"}


def build(output: Path):
    """Refuse existing output directories; never open any real history or state."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    history = output / "history.sqlite"
    store.initialize(history)
    with store.connect(history, write=True) as db:
        store.register(db, ALIAS)  # Fictional subject only.
        for label, (lat, lon) in PLACES.items():
            store.add_place(db, ALIAS, label, lat, lon, 100)
        for fix in observations():
            store.ingest(db, ALIAS, fix, received_at=fix["observed_at"] + 2)
    maintenance.compact(history)
    with store.connect(history) as db:
        before = store.statistics(db)
    maintenance.optimize(history, ALIAS, apply=True, backup_path=output / "point-baseline.sqlite")
    with store.connect(history) as db:
        after = store.statistics(db)
    day = analyze(history, ALIAS, DAY_START, DAY_END, timezone_name=ZONE, offline=True)
    month = analyze(history, ALIAS, START, END, timezone_name=ZONE, offline=True)
    example = next(item for item in month["patterns"]["candidate_windows"]
                   if item["weekday"] == "Monday" and item["hour"] == 9 and item["place"] == "Alder Studio")
    summary = {
        "synthetic": True, "network_requests": 0, "participant": ALIAS,
        "timezone": ZONE, "start_inclusive": START, "end_exclusive": END,
        "calendar_days": 28, "observed_dates": len(month["coverage"]["daily"]),
        "missing_date": "2026-09-19", "before": before, "after": after,
        "space_saved_percent": round(100 * (1 - after["database_bytes"] / before["database_bytes"]), 2),
        "example_pattern": example,
        "interpretation": "All names, coordinates, observations and patterns are invented. Missing data is not absence."
    }
    for filename, result in (("day.json", day), ("month.json", month), ("summary.json", summary)):
        (output / filename).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    transcript = render(summary, day)
    (output / "demo.txt").write_text(transcript, encoding="utf-8")
    return summary, day, month, transcript


def render(summary, day):
    before, after = summary["before"], summary["after"]
    lines = ["FindMy Ledger / synthetic offline demo", "",
             f"28 calendar days | {summary['observed_dates']} observed dates | 0 network requests",
             f"{after['samples']:,} observations -> {after['stored_rows']:,} stored rows",
             f"{before['database_bytes']:,} B -> {after['database_bytes']:,} B ({summary['space_saved_percent']}% smaller)",
             "Schema/index included; runtime, WAL, backups and place cache excluded.", "",
             "Monday, September 21 / America/New_York", "All place names and observations below are fictional.", ""]
    events = []
    for item in day["timeline"]:
        first = datetime.fromisoformat(item["first_observed_at"]).strftime("%H:%M")
        last = datetime.fromisoformat(item["last_observed_at"]).strftime("%H:%M")
        events.append((store.epoch(item["first_observed_at"]), f"  {first}-{last}  {item['place']:<17} {item['sample_count']:>3} observations"))
    for gap in day["coverage"]["gaps"]:
        local = lambda stamp: datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone(ZoneInfo(ZONE)).strftime("%H:%M")
        events.append((store.epoch(gap["after"]), f"  {local(gap['after'])}-{local(gap['before'])}  UNKNOWN: {gap['seconds'] // 60} minutes between observations"))
    lines.extend(line for _, line in sorted(events))
    pattern = summary["example_pattern"]
    lines.extend(["", "Four-week pattern example",
                  f"  {pattern['place']} appeared in {pattern['weekday']}'s {pattern['hour']:02}:00 hour on {pattern['distinct_days']} distinct dates",
                  f"  across {pattern['distinct_weeks']} weeks ({pattern['distinct_days']} of {pattern['usable_dates_in_hour']} {pattern['weekday']}s with usable evidence in that hour).",
                  "  September 19 has no observations; it is not counted as absence.", "",
                  "Observed spans are not exact arrivals/departures or proof of continuous presence.",
                  "Patterns describe location evidence, not activities or a future schedule.", ""])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("data/demo"), help="New output directory (must not exist)")
    args = parser.parse_args()
    try:
        _, _, _, transcript = build(args.output)
    except FileExistsError:
        parser.exit(2, "Output already exists. Choose a new --output directory; no files were replaced.\n")
    print(transcript, end="")
    print(f"Reports and synthetic SQLite files: {args.output}")


if __name__ == "__main__":
    main()
