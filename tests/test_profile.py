import tempfile
import unittest
from pathlib import Path

from location_ledger import store
from location_ledger.profile import weekly_profile


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "profile.sqlite"
        store.initialize(self.path)
        with store.connect(self.path, write=True) as db:
            store.register(db, "test")
            store.add_place(db, "test", "Place A", 40, -75, 100)

    def add(self, timestamp, accuracy=10):
        with store.connect(self.path, write=True) as db:
            store.ingest(db, "test", {"observed_at": timestamp, "latitude": 40,
                         "longitude": -75, "accuracy_m": accuracy, "source": "synthetic"},
                         received_at=timestamp)

    def profile(self, start="2025-10-01T00:00:00Z", end="2025-12-01T00:00:00Z"):
        with store.connect(self.path) as db:
            return weekly_profile(db, "test", start, end, timezone_name="America/New_York")

    def test_many_samples_do_not_count_as_many_dates(self):
        for timestamp in ("2025-10-06T13:00:00Z", "2025-10-06T13:05:00Z", "2025-10-13T13:00:00Z"):
            self.add(timestamp)
        result = self.profile()
        cell = result["cells"][0]
        self.assertEqual((cell["weekday"], cell["hour"]), ("Monday", 9))
        self.assertEqual(cell["dates_with_any_observation"], 2)
        self.assertEqual(cell["places"][0]["dates_with_observation"], 2)
        self.assertEqual(cell["sample_count"], 3)

    def test_repeated_dst_hour_is_one_local_date(self):
        self.add("2025-11-02T05:30:00Z")
        self.add("2025-11-02T06:30:00Z")
        cell = self.profile()["cells"][0]
        self.assertEqual(cell["hour"], 1)
        self.assertEqual(cell["dates_with_any_observation"], 1)
        self.assertEqual(cell["sample_count"], 2)

    def test_low_accuracy_does_not_assign_place(self):
        self.add("2025-10-06T13:00:00Z", accuracy=250)
        group = self.profile()["cells"][0]["places"][0]
        self.assertIsNone(group["place"])
        self.assertEqual(group["quality"], "low_accuracy")

    def test_empty_history_and_half_open_window(self):
        self.add("2025-10-06T13:00:00Z")
        self.assertEqual(self.profile(end="2025-10-06T13:00:00Z")["cells"], [])
        self.assertEqual(self.profile(end="2025-10-06T13:00:01Z")["sample_count"], 1)


if __name__ == "__main__":
    unittest.main()
