import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

from location_ledger.geocoding import (DAILY_LIMIT, POSITIVE_TTL, NEGATIVE_TTL, MAX_RESPONSE,
    PlaceCache, LookupFailure, NoRedirect, parse_photon, photon_lookup)


def feature(name="Example Library", lat=40, lon=-75, **props):
    return {"type": "Feature", "geometry": {"type": "Point", "coordinates": [lon, lat]},
            "properties": {"name": name, "street": "Example Street", "city": "Example City",
                           "osm_type": "N", "osm_id": 123, **props}}


def result(lat, lon):
    return parse_photon({"features": [feature(lat=lat/1e6, lon=lon/1e6)]}, lat, lon)


class Clock:
    def __init__(self):
        self.now = 1792000000
    def __call__(self):
        return self.now
    def sleep(self, seconds):
        self.now += seconds


class Response:
    status = 200
    def __init__(self, data):
        self.data = data
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def read(self, size):
        return self.data[:size]


class GeocodingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "places.sqlite"
        self.clock = Clock()
        self.cache = PlaceCache(self.path, clock=self.clock, sleeper=self.clock.sleep)
        self.cache.configure("test", True)
        self.area = self.cache.area("test", 40000000, -75000000, create=True)

    def resolve(self, **kwargs):
        return self.cache.resolve(self.area["id"], online=True, request_budget=[10], lookup=result, **kwargs)

    def test_positive_cache_reopened_needs_no_request(self):
        first = self.resolve()
        self.assertEqual(first["state"], "looked_up")
        reopened = PlaceCache(self.path, clock=self.clock, sleeper=self.clock.sleep)
        with patch(__name__ + ".result", side_effect=AssertionError("No HTTP expected")) as no_network:
            second = reopened.resolve(self.area["id"], online=True, request_budget=[10], lookup=no_network)
        self.assertEqual(second["result"], first["result"])
        self.assertEqual(second["state"], "cached")
        self.assertFalse(second["stale"])

    def test_negative_cache_and_expiry(self):
        budget = [10]
        lookup = lambda lat, lon: None
        first = self.cache.resolve(self.area["id"], online=True, request_budget=budget, lookup=lookup)
        self.assertEqual(first["state"], "no_match")
        self.cache.resolve(self.area["id"], online=True, request_budget=budget, lookup=lookup)
        self.assertEqual(budget[0], 9)
        self.clock.now += NEGATIVE_TTL + 1
        self.cache.resolve(self.area["id"], online=True, request_budget=budget, lookup=lookup)
        self.assertEqual(budget[0], 8)

    def test_offline_keeps_expired_name(self):
        self.resolve()
        self.clock.now += POSITIVE_TTL + 1
        resolved = self.cache.resolve(self.area["id"], online=False, request_budget=[10])
        self.assertIsNotNone(resolved["result"])
        self.assertTrue(resolved["stale"])
        self.assertEqual(resolved["state"], "offline")

    def test_global_cooldown_persists_and_honors_retry_after(self):
        def limited(*args):
            raise LookupFailure("rate_limited", 7200)
        self.cache.resolve(self.area["id"], online=True, request_budget=[10], lookup=limited)
        second = self.cache.area("test", 40010000, -75000000, create=True)
        reopened = PlaceCache(self.path, clock=self.clock, sleeper=self.clock.sleep)
        resolved = reopened.resolve(second["id"], online=True, request_budget=[10], lookup=result)
        self.assertEqual(resolved["state"], "provider_cooldown")
        self.clock.now += 7201
        self.assertEqual(reopened.resolve(second["id"], online=True, request_budget=[10], lookup=result)["state"], "looked_up")

    def test_daily_budget_and_report_budget(self):
        with self.cache.connection() as db:
            db.execute("UPDATE budget SET day=?,requests=?", (int(self.clock()//86400), DAILY_LIMIT))
        self.assertEqual(self.resolve()["state"], "daily_limit")
        self.clock.now += 86400
        self.assertEqual(self.cache.resolve(self.area["id"], online=True, request_budget=[0], lookup=result)["state"], "report_limit")
        self.assertEqual(self.resolve()["state"], "looked_up")

    def test_rate_spacing_and_only_coordinates_reach_lookup(self):
        seen = []
        def lookup(*args):
            seen.append((self.clock(), args))
            return result(*args)
        for index in range(3):
            area = self.cache.area("test", 40000000 + 10000 * index, -75000000, create=True)
            self.cache.resolve(area["id"], online=True, request_budget=[10], lookup=lookup)
        self.assertEqual([seen[i+1][0] - seen[i][0] for i in range(2)], [2, 2])
        self.assertTrue(all(len(args) == 2 and all(type(n) is int for n in args) for _, args in seen))

    def test_area_fixed_anchor_jitter_reuse_and_participant_isolation(self):
        nearby = self.cache.area("test", 40000100, -75000000, create=True)
        far = self.cache.area("test", 40001000, -75000000, create=True)
        other = self.cache.area("other", 40000000, -75000000, create=True)
        self.assertEqual(nearby["id"], self.area["id"])
        self.assertNotEqual(far["id"], self.area["id"])
        self.assertNotEqual(other["id"], self.area["id"])
        self.assertEqual(self.cache.forget("test"), 2)
        self.assertIsNotNone(self.cache.area("other", 40000000, -75000000))
        self.assertFalse(self.cache.configure("test")["online_enabled"])

    def test_area_latitude_index_and_dateline_distance(self):
        with self.cache.connection() as db:
            plan = db.execute("EXPLAIN QUERY PLAN SELECT * FROM areas WHERE participant=? AND lat_e6 BETWEEN ? AND ?", ("test", 1, 2)).fetchall()
        self.assertIn("area_position", str([tuple(r) for r in plan]))
        a = self.cache.area("test", 0, 179999950, create=True)
        b = self.cache.area("test", 0, -179999950, create=True)
        self.assertEqual(a["id"], b["id"])

    def test_parser_rejects_distant_or_invalid_geometry_and_bounds_strings(self):
        data = {"features": [feature(lat=41), feature(lat=float("nan")), feature(name="\x1b" + "x"*500)]}
        parsed = parse_photon(data, 40000000, -75000000)
        self.assertEqual(parsed["distance_m"], 0)
        self.assertNotIn("\x1b", parsed["label"])
        self.assertLess(len(parsed["label"]), 500)
        self.assertIsNone(parse_photon({"features": [feature(lat=41)]}, 40000000, -75000000))
        with self.assertRaises(LookupFailure):
            parse_photon({"features": {}}, 40000000, -75000000)

    def test_ambiguous_nearby_candidates_remain_uncertain(self):
        parsed = parse_photon({"features": [feature(), feature(name="Another Place", lat=40.0001)]}, 40000000, -75000000)
        self.assertTrue(parsed["ambiguous_nearby_features"])
        self.assertEqual(parsed["osm_url"], "https://www.openstreetmap.org/node/123")

    def test_http_request_has_no_participant_or_history(self):
        with patch("location_ledger.geocoding.build_opener") as builder:
            builder.return_value.open.return_value = Response(json.dumps({"features": [feature()]}).encode())
            photon_lookup(40000000, -75000000)
            request = builder.return_value.open.call_args.args[0]
        url = urlsplit(request.full_url)
        self.assertEqual((url.scheme, url.netloc, url.path), ("https", "photon.komoot.io", "/reverse"))
        self.assertEqual(set(parse_qs(url.query)), {"lat", "lon", "limit", "radius", "lang"})
        self.assertIsNone(request.data)
        self.assertFalse(request.has_header("Authorization"))
        with self.assertRaises(LookupFailure):
            NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.example/")

    def test_http_failures_redacted_and_bounded(self):
        with patch("location_ledger.geocoding.build_opener") as builder:
            builder.return_value.open.side_effect = HTTPError("secret-url", 429, "sensitive", {"Retry-After": "7200"}, None)
            with self.assertRaises(LookupFailure) as caught:
                photon_lookup(40000000, -75000000)
            self.assertEqual(str(caught.exception), "rate_limited")
            self.assertEqual(caught.exception.retry_after, 7200)
        for body in (b"{" + b"x" * MAX_RESPONSE, b"not JSON", b'{"features":null}'):
            with patch("location_ledger.geocoding.build_opener") as builder:
                builder.return_value.open.return_value = Response(body)
                with self.assertRaises(LookupFailure):
                    photon_lookup(40000000, -75000000)


if __name__ == "__main__":
    unittest.main()
