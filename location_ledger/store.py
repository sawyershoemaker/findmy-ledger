from __future__ import annotations

import math
import sqlite3
import time
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE subjects (
    id INTEGER PRIMARY KEY,
    alias TEXT NOT NULL UNIQUE,
    consent_at INTEGER NOT NULL,
    active INTEGER NOT NULL CHECK(active IN (0,1))
);
CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
CREATE TABLE samples (
    subject_id INTEGER NOT NULL REFERENCES subjects(id),
    observed_at INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    lat_e6 INTEGER NOT NULL CHECK(lat_e6 BETWEEN -90000000 AND 90000000),
    lon_e6 INTEGER NOT NULL CHECK(lon_e6 BETWEEN -180000000 AND 180000000),
    accuracy_dm INTEGER NOT NULL CHECK(accuracy_dm >= 0),
    source_id INTEGER NOT NULL REFERENCES sources(id),
    span_seconds INTEGER NOT NULL DEFAULT 0 CHECK(span_seconds >= 0),
    fix_count INTEGER NOT NULL DEFAULT 1 CHECK(fix_count >= 1),
    detail BLOB,
    PRIMARY KEY(subject_id, observed_at)
) WITHOUT ROWID;
CREATE TABLE places (
    id INTEGER PRIMARY KEY,
    subject_id INTEGER NOT NULL REFERENCES subjects(id),
    label TEXT NOT NULL,
    lat_e6 INTEGER NOT NULL,
    lon_e6 INTEGER NOT NULL,
    radius_m INTEGER NOT NULL CHECK(radius_m > 0),
    UNIQUE(subject_id, label)
);
PRAGMA user_version=2;
"""


def epoch(value) -> int:
    if isinstance(value, bool):
        raise ValueError("Timestamp must be UTC Unix seconds or ISO 8601 with an offset")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("Timestamp needs an explicit UTC offset")
        result = int(parsed.timestamp())
    else:
        raise ValueError("Timestamp must be integer seconds or ISO 8601")
    if not 946684800 <= result <= 4102444800:
        raise ValueError("Timestamp outside 2000-2100; check epoch and units")
    return result


def iso(value: int) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


def number(value, low, high, label):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be numeric")
    if not math.isfinite(value) or not low <= value <= high:
        raise ValueError(f"Invalid {label}")
    return float(value)


def text_label(value, label):
    if not isinstance(value, str) or not value.strip() or len(value) > 100:
        raise ValueError(f"{label} must contain 1-100 characters")
    if any(ord(c) < 32 for c in value):
        raise ValueError(f"{label} must not contain control characters")
    return value.strip()


def initialize(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Fail if a database already exists; never overwrite someone's history.
    with path.open("xb"):
        pass
    with closing(sqlite3.connect(path)) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.executescript(SCHEMA)


@contextmanager
def connect(path, *, write=False, timeout=10):
    path = Path(path).resolve()
    mode = "rw" if write else "ro"
    db = sqlite3.connect(path.as_uri() + "?mode=" + mode, uri=True, timeout=timeout)
    db.row_factory = sqlite3.Row
    try:
        if db.execute("PRAGMA user_version").fetchone()[0] not in (1, 2):
            raise ValueError("Not a supported Location Ledger database")
        db.execute("PRAGMA foreign_keys=ON")
        if write:
            db.execute("PRAGMA synchronous=FULL")
        if not write:
            db.execute("PRAGMA query_only=ON")
            # A stay range uses a predecessor seek plus a range seek. Keep both
            # reads, counts, and labels on one WAL snapshot while Live writes.
            db.execute('BEGIN')
        with db:
            yield db
    finally:
        db.close()


def subject(db, alias, *, require_active=False):
    row = db.execute("SELECT * FROM subjects WHERE alias=?", (alias,)).fetchone()
    if row is None:
        raise ValueError("Unknown participant; register them first")
    if require_active and not row["active"]:
        raise ValueError("Collection is paused for this participant")
    return row


def register(db, alias):
    # Keep the legacy timestamp column for existing histories and backups.
    # It records registration/resume time, not an acknowledgement requirement.
    alias = text_label(alias, "Participant alias")
    db.execute("INSERT INTO subjects(alias,consent_at,active) VALUES(?,?,1)", (alias, int(time.time())))


def normalize_observation(observation, *, received_at=None):
    """Validate and quantize one fix without changing the database."""
    observed = epoch(observation["observed_at"])
    received = int(time.time()) if received_at is None else epoch(received_at)
    if observed > received + 300:
        raise ValueError("Location timestamp is more than five minutes in the future")
    lat = round(number(observation["latitude"], -90, 90, "latitude") * 1_000_000)
    lon = round(number(observation["longitude"], -180, 180, "longitude") * 1_000_000)
    acc = round(number(observation["accuracy_m"], 0, 1_000_000, "accuracy") * 10)
    source = text_label(observation["source"], "Source")
    return observed, received, lat, lon, acc, source


def ingest(db, alias, observation, *, received_at=None):
    sid = subject(db, alias, require_active=True)["id"]
    observed, received, lat, lon, acc, source = normalize_observation(observation, received_at=received_at)
    db.execute("INSERT OR IGNORE INTO sources(name) VALUES(?)", (source,))
    source_id = db.execute("SELECT id FROM sources WHERE name=?", (source,)).fetchone()[0]
    if db.execute("PRAGMA user_version").fetchone()[0] == 2:
        from .history import insert_exact
        return insert_exact(db, sid, (observed, received, lat, lon, acc), source_id)
    old = db.execute("SELECT lat_e6,lon_e6,accuracy_dm,source_id FROM samples WHERE subject_id=? AND observed_at=?", (sid, observed)).fetchone()
    if old is not None:
        if tuple(old) != (lat, lon, acc, source_id):
            raise ValueError("Conflicting location at the same source timestamp; inspect the adapter")
        return False
    db.execute("INSERT INTO samples VALUES(?,?,?,?,?,?,?)", (sid, observed, received, lat, lon, acc, source_id))
    return True


def add_place(db, alias, label, lat, lon, radius_m):
    sid = subject(db, alias)["id"]
    label = text_label(label, "Place label")
    lat = round(number(lat, -90, 90, "latitude") * 1_000_000)
    lon = round(number(lon, -180, 180, "longitude") * 1_000_000)
    radius = round(number(radius_m, 1, 100000, "radius"))
    db.execute("INSERT INTO places(subject_id,label,lat_e6,lon_e6,radius_m) VALUES(?,?,?,?,?) ON CONFLICT(subject_id,label) DO UPDATE SET lat_e6=excluded.lat_e6,lon_e6=excluded.lon_e6,radius_m=excluded.radius_m", (sid, label, lat, lon, radius))


def distance_m(lat1, lon1, lat2, lon2):
    a, b = math.radians(lat1), math.radians(lat2)
    dlat, dlon = b - a, math.radians(lon2 - lon1)
    hav = math.sin(dlat / 2) ** 2 + math.cos(a) * math.cos(b) * math.sin(dlon / 2) ** 2
    return 6371008.8 * 2 * math.asin(min(1.0, math.sqrt(hav)))


def classify(sample, places, max_accuracy):
    accuracy = sample["accuracy_dm"] / 10
    if accuracy > max_accuracy:
        return None, "low_accuracy"
    candidates = []
    for place in places:
        distance = distance_m(sample["lat_e6"] / 1e6, sample["lon_e6"] / 1e6,
                              place["lat_e6"] / 1e6, place["lon_e6"] / 1e6)
        # A location whose accuracy circle crosses the boundary is ambiguous.
        if distance + accuracy <= place["radius_m"]:
            candidates.append(place["label"])
    if len(candidates) == 1:
        return candidates[0], "within_labelled_place"
    return None, "overlapping_places" if candidates else "unlabelled_or_boundary"


def report(db, alias, start, end, *, max_gap=600, max_accuracy=100):
    from .history import Run, range_rows
    start, end = epoch(start), epoch(end)
    if start >= end or end - start > 366 * 86400:
        raise ValueError("Choose a positive report interval of at most 366 days")
    if max_gap <= 0 or max_accuracy <= 0:
        raise ValueError("Gap and accuracy thresholds must be positive")
    sid = subject(db, alias)["id"]
    places = db.execute("SELECT * FROM places WHERE subject_id=?", (sid,)).fetchall()
    rows = range_rows(db, sid, start, end)
    spans, gaps, current = [], [], None
    count, previous, latest_received = 0, None, None
    for row in rows:
        run = Run.from_row(row).slice(start, end)
        if run is None:
            continue
        latest_received = max(latest_received or 0, run.received_at)
        label, quality = classify(row, places, max_accuracy)
        for times in run.times.groups(max_gap):
            count += times.count
            ts, last = times.first, times.last
            if previous is not None and ts - previous > max_gap:
                gaps.append({"after": iso(previous), "before": iso(ts), "seconds": ts - previous})
            # Previously all unlabelled fixes could collapse into one span even
            # when miles apart. Unknown places also require spatial proximity.
            same_location = current is not None and (label is not None or
                (quality != 'low_accuracy' and distance_m(anchor[0]/1e6, anchor[1]/1e6,
                    run.lat_e6/1e6, run.lon_e6/1e6) <= 25))
            same_span = (same_location and current['place'] == label and current['quality'] == quality
                         and ts - previous <= max_gap)
            if not same_span:
                anchor = (run.lat_e6, run.lon_e6)
                current = {'place': label, 'quality': quality, 'first_observed_at': iso(ts),
                    'last_observed_at': iso(last), 'sample_count': times.count,
                    'observed_span_seconds': last-ts, 'compacted_stay': run.times.count > 1}
                spans.append(current)
            else:
                current['observed_span_seconds'] += last - previous
                current['last_observed_at'] = iso(last)
                current['sample_count'] += times.count
                current['compacted_stay'] |= run.times.count > 1
            previous = last
    return {
        "participant": alias, "start_inclusive": iso(start), "end_exclusive": iso(end),
        "timezone": "UTC", "sample_count": count, "spans": spans, "gaps": gaps,
        "last_receipt_at": iso(latest_received) if latest_received else None,
        "method": {"max_gap_seconds": max_gap, "max_accuracy_m": max_accuracy,
                   "coordinates_in_report": False, "labels": "manually supplied",
                   "stationary_coordinates": "fixed anchor with conservative uncertainty envelope",
                   "timing_and_counts": "exact source timestamps, including compacted evidence"},
        "interpretation": [
            "Times are observations, not exact arrivals or departures.",
            "A span assumes no unobserved departure between nearby samples; it is not proof of continuous presence.",
            "Long gaps and low-accuracy samples split spans. Missing observations are not evidence of staying put.",
            "Device location alone does not establish activity, intent, or that the person carried the device.",
            "The first and last observations may fall inside a longer stay; the report window can truncate it.",
        ],
    }


def statistics(db):
    version = db.execute('PRAGMA user_version').fetchone()[0]
    rows = db.execute('SELECT count(*) FROM samples').fetchone()[0]
    count = db.execute('SELECT COALESCE(sum(fix_count),0) FROM samples').fetchone()[0] if version == 2 else rows
    stays = db.execute('SELECT count(*) FROM samples WHERE fix_count>1').fetchone()[0] if version == 2 else 0
    pages = db.execute("PRAGMA page_count").fetchone()[0]
    size = db.execute("PRAGMA page_size").fetchone()[0]
    return {"samples": count, "stored_rows": rows, "stationary_runs": stays, 'schema_version': version,
            "database_bytes": pages * size, 'freelist_pages': db.execute('PRAGMA freelist_count').fetchone()[0],
            "bytes_per_sample_including_schema": round(pages * size / count, 2) if count else None}
