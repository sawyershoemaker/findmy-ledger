import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from research.ngm_replay import reserve_counter


class ReplayCounterTests(unittest.TestCase):
    def test_crash_gap_and_restart_never_reuse_reserved_counter(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "counter.dpapi"
            saved = {}
            def save(destination, state):
                saved.clear()
                saved.update(copy.deepcopy(state))
                destination.touch()
            with patch("research.ngm_replay.load", side_effect=lambda p: copy.deepcopy(saved)), \
                 patch("research.ngm_replay.save_atomic", side_effect=save):
                keys = (b"a"*32, b"b"*32, b"c"*32)
                self.assertEqual(reserve_counter(path, *keys), 0)
                # No send happened. A fresh reservation still burns zero.
                self.assertEqual(reserve_counter(path, *keys), 1)
                self.assertEqual(reserve_counter(path, *keys), 2)
                # A different peer prekey has an independent native stream.
                self.assertEqual(reserve_counter(path, keys[0], keys[1], b"d"*32), 0)

    def test_failed_durable_write_and_corrupt_store_never_return_counter(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "counter.dpapi"
            keys = (b"a"*32, b"b"*32, b"c"*32)
            with patch("research.ngm_replay.save_atomic", side_effect=OSError):
                with self.assertRaises(OSError):
                    reserve_counter(path, *keys)
            path.touch()
            with patch("research.ngm_replay.load", return_value={"version": 99, "next": {}}):
                with self.assertRaises(ValueError):
                    reserve_counter(path, *keys)
            with self.assertRaises(ValueError):
                reserve_counter(path, b"short", keys[1], keys[2])
