import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from research.demo import build, observations


class PublicDemoTests(unittest.TestCase):
    def test_offline_compaction_preserves_evidence_and_gap(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch("socket.socket.connect", side_effect=AssertionError("Demo must stay offline")):
                summary, day, month, transcript = build(Path(temp) / "demo")
            count = len(list(observations()))
            self.assertEqual(summary["before"]["samples"], count)
            self.assertEqual(summary["after"]["samples"], count)
            self.assertLess(summary["after"]["stored_rows"], count // 10)
            self.assertEqual(day["sample_count"], 111)
            self.assertEqual([gap["seconds"] for gap in day["coverage"]["gaps"]], [3000])
            self.assertEqual(len(month["coverage"]["daily"]), 27)
            self.assertNotIn("2026-09-19", month["patterns"]["dates_with_any_observation"])
            self.assertEqual(summary["example_pattern"]["distinct_days"], 4)
            self.assertIn("UNKNOWN", transcript)
            self.assertEqual(day["geocoding"]["requests_this_report"], 0)
            self.assertEqual(month["geocoding"]["requests_this_report"], 0)

    def test_existing_directory_is_untouched(self):
        with tempfile.TemporaryDirectory() as temp:
            sentinel = Path(temp) / "keep.txt"
            sentinel.write_text("keep", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                build(Path(temp))
            self.assertEqual(sentinel.read_text(), "keep")
            self.assertEqual(len(list(Path(temp).iterdir())), 1)
