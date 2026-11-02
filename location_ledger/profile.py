"""Read-only summaries of repeated observations, with no activity inference."""
from collections import defaultdict
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import store


def weekly_profile(db, alias, start, end, *, timezone_name, max_accuracy=100):
    from .history import Run, range_rows
    start, end = store.epoch(start), store.epoch(end)
    if start >= end or end - start > 366 * 86400:
        raise ValueError("Choose a positive interval of at most 366 days")
    if max_accuracy <= 0:
        raise ValueError("Accuracy threshold must be positive")
    try:
        zone = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as error:
        raise ValueError("Unknown time zone, or tzdata is not installed") from error
    sid = store.subject(db, alias)["id"]
    places = db.execute("SELECT * FROM places WHERE subject_id=?", (sid,)).fetchall()
    rows = range_rows(db, sid, start, end)
    observed_days = set()
    cells = defaultdict(lambda: {"dates": set(), "samples": 0, "groups": {}})
    total = 0
    for row in rows:
        label, quality = store.classify(row, places, max_accuracy)
        for first, step, count in Run.from_row(row).times.series(start, end):
            while count:
                # Batch dense streams within UTC minutes. A zone transition or
                # repeated local hour never turns a missing timestamp into data.
                boundary = (first // 60 + 1) * 60
                batch = min(count, (boundary - first + step - 1) // step)
                local = datetime.fromtimestamp(first, zone)
                date = local.date().isoformat()
                observed_days.add(date)
                cell = cells[local.weekday(), local.hour]
                cell['dates'].add(date)
                cell['samples'] += batch
                total += batch
                group = cell['groups'].setdefault((label, quality), {'dates': set(), 'samples': 0})
                group['dates'].add(date)
                group['samples'] += batch
                first += batch * step
                count -= batch
    result = []
    weekdays = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
    for (weekday, hour), cell in sorted(cells.items()):
        result.append({
            "weekday": weekdays[weekday], "hour": hour,
            "dates_with_any_observation": len(cell["dates"]),
            "sample_count": cell["samples"],
            "places": [{"place": label, "quality": quality,
                        "dates_with_observation": len(group["dates"]),
                        "sample_count": group["samples"]}
                       for (label, quality), group in sorted(cell["groups"].items(), key=lambda item: (item[0][0] or "", item[0][1]))],
        })
    return {
        "participant": alias, "start_inclusive": store.iso(start), "end_exclusive": store.iso(end),
        "timezone": timezone_name, "sample_count": total,
        "dates_with_observations": sorted(observed_days), "cells": result,
        "method": {"max_accuracy_m": max_accuracy, "coordinates_in_report": False,
                   "unit": "distinct local dates with at least one observation in that hour"},
        "interpretation": [
            "Counts measure observed presence, not time spent, activity, or a confirmed schedule.",
            "Multiple places can be observed in the same hour, so their date counts can overlap.",
            "Dates with no data are absent. The denominator is observed dates, not all calendar dates.",
            "Repeated samples on one day do not count as additional days. Repeated DST hours share one date count.",
            "Use the chronological report to inspect gaps and observation spans before explaining a pattern.",
        ],
    }
