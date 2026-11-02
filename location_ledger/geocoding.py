"""Free, bounded Photon reverse lookup and a small, participant-scoped area cache.

No Apple identifier, alias, time range or history is sent to the provider. The
only variable request fields are a representative latitude and longitude.
"""
from contextlib import contextmanager
from email.utils import parsedate_to_datetime
import json
import math
from pathlib import Path
import sqlite3
import time
import unicodedata
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, HTTPRedirectHandler, build_opener

from . import store

ENDPOINT = "https://photon.komoot.io/reverse"
ATTRIBUTION = "© OpenStreetMap contributors; geocoding by Photon / komoot"
AREA_RADIUS_M = 50
DAILY_LIMIT = 60
REPORT_LIMIT = 10
MIN_INTERVAL = 2
POSITIVE_TTL = 180 * 86400
NEGATIVE_TTL = 7 * 86400
MAX_RESPONSE = 128 * 1024

SCHEMA = """
CREATE TABLE preferences (
    participant TEXT PRIMARY KEY, online INTEGER NOT NULL DEFAULT 0 CHECK(online IN (0,1))
) WITHOUT ROWID;
CREATE TABLE areas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    participant TEXT NOT NULL REFERENCES preferences(participant),
    lat_e6 INTEGER NOT NULL, lon_e6 INTEGER NOT NULL,
    result TEXT, checked_at INTEGER, next_lookup_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX area_position ON areas(participant,lat_e6);
CREATE TABLE budget (
    id INTEGER PRIMARY KEY CHECK(id=1), day INTEGER NOT NULL, requests INTEGER NOT NULL,
    next_request_at REAL NOT NULL, blocked_until REAL NOT NULL
);
INSERT INTO budget VALUES(1,0,0,0,0);
PRAGMA user_version=1;
"""


def cache_path(history_path):
    path = Path(history_path)
    return path.with_name(path.stem + ".places.sqlite")


def clean_text(value):
    if not isinstance(value, str):
        return ""
    # Keep labels as bounded, inert data; never persist provider markup/control codes.
    return " ".join("".join(c for c in value if not unicodedata.category(c).startswith("C")).split())[:160]


class LookupFailure(Exception):
    def __init__(self, reason, retry_after=0):
        super().__init__(reason)  # Allowlisted text only: never a URL or response body.
        self.reason = reason
        self.retry_after = retry_after


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise LookupFailure("redirect_refused")


def retry_seconds(value, now):
    try:
        if str(value).isdigit():
            return max(0, int(value))
        return max(0, int(parsedate_to_datetime(value).timestamp() - now))
    except (TypeError, ValueError, OverflowError):
        return 0


def photon_lookup(lat_e6, lon_e6):
    # TLS validation stays enabled. No dynamic host, auth, referrer or cookie jar.
    query = urlencode({"lat": f"{lat_e6 / 1e6:.6f}", "lon": f"{lon_e6 / 1e6:.6f}",
                       "limit": 5, "radius": 0.25, "lang": "en"})
    request = Request(ENDPOINT + "?" + query, headers={
        "User-Agent": "FindMyLedger/0.1 (local cached place summaries)", "Accept": "application/json"})
    try:
        with build_opener(NoRedirect()).open(request, timeout=12) as response:
            if response.status != 200:
                raise LookupFailure("http_error")
            raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise LookupFailure("oversized_response")
        return parse_photon(json.loads(raw), lat_e6, lon_e6)
    except HTTPError as error:
        raise LookupFailure("rate_limited" if error.code == 429 else "http_error",
                            retry_seconds(error.headers.get("Retry-After"), time.time())) from None
    except (URLError, OSError, TimeoutError):
        raise LookupFailure("network_error") from None
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise LookupFailure("invalid_response") from None


def parse_photon(data, lat_e6, lon_e6):
    if not isinstance(data, dict) or not isinstance(data.get("features"), list) or len(data["features"]) > 100:
        raise LookupFailure("invalid_response")
    candidates = []
    for feature in data["features"]:
        if not isinstance(feature, dict):
            continue
        geom, props = feature.get("geometry"), feature.get("properties")
        if not isinstance(geom, dict) or geom.get("type") != "Point" or not isinstance(props, dict):
            continue
        coords = geom.get("coordinates")
        if not isinstance(coords, list) or len(coords) != 2:
            continue
        lon, lat = coords
        if (type(lat) not in (int, float) or type(lon) not in (int, float)
                or not math.isfinite(lat) or not math.isfinite(lon) or not -90 <= lat <= 90 or not -180 <= lon <= 180):
            continue
        distance = store.distance_m(lat_e6/1e6, lon_e6/1e6, lat, lon)
        if distance > 250:
            continue
        fields = {k: clean_text(props.get(k)) for k in (
            "name", "street", "housenumber", "city", "district", "state", "country", "osm_key", "osm_value")}
        address = " ".join(filter(None, (fields["housenumber"], fields["street"])))
        title = fields["name"] or address or fields["district"] or fields["city"]
        if not title:
            continue
        context = ", ".join(dict.fromkeys(v for v in (address, fields["city"], fields["state"]) if v and v != title))
        osm_type, osm_id = props.get("osm_type"), props.get("osm_id")
        osm_url = None
        if osm_type in ("N", "W", "R") and type(osm_id) is int and 0 < osm_id < 10**15:
            osm_url = f"https://www.openstreetmap.org/{ {'N':'node', 'W':'way', 'R':'relation'}[osm_type] }/{osm_id}"
        candidates.append({"label": title + (", " + context if context else ""),
                           "distance_m": round(distance, 1), "osm_url": osm_url,
                           "kind": ":".join(filter(None, (fields["osm_key"], fields["osm_value"]))) or "mapped_feature"})
    candidates.sort(key=lambda item: item["distance_m"])
    if not candidates:
        return None
    chosen = candidates[0]
    # No false venue certainty: even a single close candidate is merely nearby.
    chosen["ambiguous_nearby_features"] = any(
        c["label"] != chosen["label"] and c["distance_m"] <= chosen["distance_m"] + 50 for c in candidates[1:])
    return chosen


class PlaceCache:
    def __init__(self, path, *, clock=time.time, sleeper=time.sleep):
        self.path = Path(path)
        self.clock, self.sleeper = clock, sleeper
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                for statement in SCHEMA.split(";"):
                    if statement.strip():
                        db.execute(statement)
            elif version != 1:
                raise ValueError("Unsupported place cache")

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys=ON")
            with db:
                yield db
        finally:
            db.close()

    def configure(self, participant, online=None):
        with self.connection() as db:
            db.execute("INSERT OR IGNORE INTO preferences(participant) VALUES(?)", (participant,))
            if online is not None:
                db.execute("UPDATE preferences SET online=? WHERE participant=?", (int(online), participant))
            enabled = bool(db.execute("SELECT online FROM preferences WHERE participant=?", (participant,)).fetchone()[0])
        return {"participant": participant, "online_enabled": enabled, "provider": "Photon public API",
                "free_only": True, "billing_configured": False, "paid_fallback": False,
                "daily_request_limit": DAILY_LIMIT, "per_report_limit": REPORT_LIMIT,
                "minimum_request_interval_seconds": MIN_INTERVAL, "positive_cache_days": POSITIVE_TTL // 86400,
                "cache": str(self.path), "attribution": ATTRIBUTION}

    def area(self, participant, lat, lon, *, spread_m=0, create=False):
        # Small B-tree latitude band, followed by exact geodesic distance. No
        # per-observation place index, route geometry, or duplicate name strings.
        band = math.ceil(AREA_RADIUS_M / 110000 * 1e6)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            candidates = db.execute("SELECT * FROM areas WHERE participant=? AND lat_e6 BETWEEN ? AND ?",
                                    (participant, lat - band, lat + band)).fetchall()
            nearby = [(store.distance_m(lat/1e6, lon/1e6, r["lat_e6"]/1e6, r["lon_e6"]/1e6), r) for r in candidates]
            nearby = [(d, r) for d, r in nearby if d + spread_m <= AREA_RADIUS_M]
            if nearby:
                return dict(min(nearby, key=lambda pair: (pair[0], pair[1]["id"]))[1])
            if not create or spread_m > AREA_RADIUS_M:
                return None
            db.execute("INSERT OR IGNORE INTO preferences(participant) VALUES(?)", (participant,))
            cursor = db.execute("INSERT INTO areas(participant,lat_e6,lon_e6) VALUES(?,?,?)", (participant, lat, lon))
            return dict(db.execute("SELECT * FROM areas WHERE id=?", (cursor.lastrowid,)).fetchone())

    def resolve(self, area_id, *, online, request_budget, lookup=photon_lookup):
        def existing(row, state):
            result = json.loads(row["result"]) if row["result"] else None
            return {"result": result, "state": state, "checked_at": row["checked_at"],
                    "stale": bool(row["checked_at"] and self.clock() >= row["checked_at"] + POSITIVE_TTL)}
        while True:
            now = self.clock()
            with self.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT * FROM areas WHERE id=?", (area_id,)).fetchone()
                if row is None:
                    raise ValueError("Unknown cached area")
                if row["next_lookup_at"] > now:
                    return existing(row, "cached" if row["checked_at"] else "deferred")
                if not online:
                    return existing(row, "offline")
                if request_budget[0] <= 0:
                    return existing(row, "report_limit")
                budget = db.execute("SELECT * FROM budget WHERE id=1").fetchone()
                used = budget["requests"] if budget["day"] == int(now // 86400) else 0
                if budget["blocked_until"] > now:
                    return existing(row, "provider_cooldown")
                if used >= DAILY_LIMIT:
                    return existing(row, "daily_limit")
                delay = budget["next_request_at"] - now
                if delay <= 0:
                    db.execute("UPDATE budget SET day=?,requests=?,next_request_at=? WHERE id=1",
                               (int(now // 86400), used + 1, now + MIN_INTERVAL))
                    # Suppress duplicate concurrent requests for the same area.
                    db.execute("UPDATE areas SET next_lookup_at=? WHERE id=?", (int(now) + 120, area_id))
                    request_budget[0] -= 1
                    break
            self.sleeper(min(delay, MIN_INTERVAL))
        try:
            result = lookup(row["lat_e6"], row["lon_e6"])
        except LookupFailure as error:
            now = self.clock()
            cooldown = max(3600 if error.reason == "rate_limited" else 900, error.retry_after)
            with self.connection() as db:
                db.execute("UPDATE budget SET blocked_until=max(blocked_until,?) WHERE id=1", (now + cooldown,))
                db.execute("UPDATE areas SET next_lookup_at=? WHERE id=?", (int(now + cooldown), area_id))
            return existing(row, error.reason)
        now = int(self.clock())
        with self.connection() as db:
            db.execute("UPDATE areas SET result=?,checked_at=?,next_lookup_at=? WHERE id=?",
                       (json.dumps(result, ensure_ascii=False, separators=(",", ":")) if result else None,
                        now, now + (POSITIVE_TTL if result else NEGATIVE_TTL), area_id))
        return {"result": result, "state": "looked_up" if result else "no_match", "checked_at": now, "stale": False}

    def forget(self, participant):
        with self.connection() as db:
            db.execute("PRAGMA secure_delete=ON")
            cursor = db.execute("DELETE FROM areas WHERE participant=?", (participant,))
            db.execute("DELETE FROM preferences WHERE participant=?", (participant,))
            return cursor.rowcount
