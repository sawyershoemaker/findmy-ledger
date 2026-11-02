import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from location_ledger import store, maintenance
from location_ledger.analysis import analyze
from location_ledger.geocoding import PlaceCache, cache_path, parse_photon
from location_ledger.history import StayPolicy


def lookup(lat, lon):
    return parse_photon({"features": [{"geometry": {"type": "Point", "coordinates": [lon/1e6, lat/1e6]},
        "properties": {"name": "Example A" if lat < 40010000 else "Example B"}}]}, lat, lon)


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "history.sqlite"
        store.initialize(self.path)
        with store.connect(self.path, write=True) as db:
            store.register(db, "test")
        self.cache = PlaceCache(cache_path(self.path))
        self.cache.configure("test", True)

    def add(self, timestamp, lat=40, lon=-75, accuracy=10):
        with store.connect(self.path, write=True) as db:
            store.ingest(db, "test", {"observed_at": timestamp, "latitude": lat, "longitude": lon,
                         "accuracy_m": accuracy, "source": "synthetic"}, received_at=timestamp)

    def report(self, **kwargs):
        return analyze(self.path, "test", kwargs.pop("start", "2025-10-01T00:00:00Z"),
                       kwargs.pop("end", "2025-12-01T00:00:00Z"), timezone_name="America/New_York",
                       cache=self.cache, lookup=kwargs.pop("lookup", lookup), **kwargs)

    def test_named_timeline_transition_return_and_reuse(self):
        for stamp, lat in (("13:00", 40), ("13:05", 40.00005), ("13:10", 40.02),
                           ("13:15", 40.02), ("13:20", 40), ("13:25", 40)):
            self.add("2025-10-06T" + stamp + ":00Z", lat=lat)
        spy = Mock(side_effect=lookup)
        first = self.report(lookup=spy)
        self.assertEqual(first["sample_count"], 6)
        self.assertEqual(len(first["timeline"]), 3)
        self.assertEqual(len(first["places"]), 2)
        self.assertEqual(len(first["transitions"]), 2)
        self.assertEqual(spy.call_count, 2)
        self.assertEqual(first["timeline"][0]["place"], "Near Example A")
        self.assertEqual(first["timeline"][0]["first_observed_at"], "2025-10-06T09:00:00-04:00")
        second = self.report(lookup=Mock(side_effect=AssertionError("Unexpected request")))
        self.assertEqual(first["timeline"], second["timeline"])
        self.assertEqual(second["geocoding"]["requests_this_report"], 0)
        self.assertNotIn("lat_e6", json.dumps(first))
        self.assertNotIn('"lon"', json.dumps(first))

    def test_long_gap_and_poor_accuracy_split_stays(self):
        for stamp, accuracy in (("13:00", 10), ("13:05", 10), ("13:25", 10), ("13:30", 300), ("13:35", 10)):
            self.add("2025-10-06T" + stamp + ":00Z", accuracy=accuracy)
        data = self.report()
        self.assertEqual(len(data["timeline"]), 4)
        self.assertEqual(data["coverage"]["gaps"][0]["seconds"], 1200)
        self.assertEqual(data["timeline"][2]["quality"], "low_accuracy")
        self.assertIsNone(data["timeline"][2]["place_id"])
        self.assertEqual(data["patterns"]["status"], "insufficient_repeated_evidence")

    def test_short_movement_creates_no_areas_or_lookups(self):
        for index in range(30):
            self.add(store.epoch("2025-10-06T13:00:00Z") + index, lat=40 + index * 0.001)
        spy = Mock(side_effect=AssertionError("No request for travel points"))
        data = self.report(lookup=spy)
        self.assertEqual(data["sample_count"], 30)
        self.assertEqual(data["places"], {})
        with self.cache.connection() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM areas").fetchone()[0], 0)

    def test_compacted_partial_window_exact_counts_and_no_history_mutation(self):
        base = store.epoch("2025-10-06T13:00:00Z")
        for index in range(601):
            self.add(base + index, lat=40 + (index % 3) / 1e6)
        maintenance.optimize(self.path, "test", policy=StayPolicy(), apply=True)
        with store.connect(self.path) as db:
            before = [tuple(r) for r in db.execute("SELECT * FROM samples")]
        data = self.report(start=base+100, end=base+401)
        self.assertEqual(data["sample_count"], 301)
        self.assertEqual(len(data["timeline"]), 1)
        self.assertEqual(data["timeline"][0]["observed_span_seconds"], 300)
        self.assertTrue(data["timeline"][0]["window_clips_stored_segment_start"])
        self.assertTrue(data["timeline"][0]["window_clips_stored_segment_end"])
        with store.connect(self.path) as db:
            self.assertEqual(before, [tuple(r) for r in db.execute("SELECT * FROM samples")])

    def test_monthly_patterns_use_days_and_coverage_not_dense_sample_counts(self):
        for day in (6, 13, 20):
            for second in range(0, 301, 60):
                self.add(store.epoch(f"2025-10-{day:02d}T13:00:00Z") + second)
        for second in range(301):
            self.add(store.epoch("2025-10-27T13:00:00Z") + second, lat=40.02)
        data = self.report()
        candidate = data["patterns"]["candidate_windows"][0]
        self.assertEqual((candidate["weekday"], candidate["hour"]), ("Monday", 9))
        self.assertEqual(candidate["distinct_days"], 3)
        self.assertEqual(candidate["distinct_weeks"], 3)
        self.assertEqual(candidate["usable_dates_in_hour"], 4)
        self.assertEqual(candidate["fraction_of_usable_dates_in_hour"], 0.75)
        self.assertEqual(candidate["sample_count"], 18)
        self.assertEqual(len(data["patterns"]["candidate_windows"]), 1)

    def test_dst_fold_one_date_and_timezone_counts(self):
        for stamp in ("05:30", "05:35", "06:30", "06:35"):
            self.add("2025-11-02T" + stamp + ":00Z")
        data = self.report()
        cell = data["patterns"]["hourly_evidence"][0]
        self.assertEqual(cell["hour"], 1)
        self.assertEqual(cell["dates_with_usable_observation"], 1)
        self.assertEqual(cell["places"][0]["distinct_days"], 1)
        self.assertEqual(cell["places"][0]["sample_count"], 4)
        self.assertEqual(data["coverage"]["daily"][0]["minutes_with_observations"], 4)
        self.assertTrue(data["timeline"][0]["first_observed_at"].endswith("-04:00"))
        self.assertTrue(data["timeline"][1]["first_observed_at"].endswith("-05:00"))

    def test_manual_labels_override_map_and_dont_trigger_request(self):
        with store.connect(self.path, write=True) as db:
            store.add_place(db, "test", "User chosen place", 40, -75, 100)
        self.add("2025-10-06T13:00:00Z")
        self.add("2025-10-06T13:05:00Z")
        data = self.report(lookup=Mock(side_effect=AssertionError("No lookup")))
        self.assertEqual(data["timeline"][0]["place"], "User chosen place")
        self.assertEqual(next(iter(data["places"].values()))["basis"], "user_supplied_label")

    def test_paused_participant_and_offline_flag_block_external_requests(self):
        self.add("2025-10-06T13:00:00Z")
        self.add("2025-10-06T13:05:00Z")
        no_network = Mock(side_effect=AssertionError("No lookup"))
        self.assertEqual(self.report(offline=True, lookup=no_network)["geocoding"]["requests_this_report"], 0)
        with store.connect(self.path, write=True) as db:
            db.execute("UPDATE subjects SET active=0")
        self.assertEqual(self.report(lookup=no_network)["geocoding"]["requests_this_report"], 0)

    def test_empty_history_and_window_validation(self):
        data = self.report()
        self.assertEqual(data["sample_count"], 0)
        self.assertEqual(data["timeline"], [])
        self.assertEqual(data["patterns"]["candidate_windows"], [])
        with self.assertRaises(ValueError):
            self.report(start="2025-01-01T00:00:00Z", end="2027-01-01T00:00:00Z")
        with self.assertRaises(ValueError):
            self.report(start="2025-10-01T00:00:00")


if __name__ == "__main__":
    unittest.main()
