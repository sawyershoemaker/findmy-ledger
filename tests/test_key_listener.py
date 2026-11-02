import asyncio
import base64
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from research.key_listener import next_request_allowed, selection_ready

try:
    from research.key_probe import save_delivery
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
except ImportError:
    save_delivery = None


class ListenerGatesTests(unittest.TestCase):
    def test_legacy_acknowledgement_does_not_gate_selection_but_pause_still_does(self):
        from location_ledger import store
        expected = {"alias": "synthetic", "account_dsid": "synthetic-account"}
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            database = directory / "history.sqlite"
            store.initialize(database)
            with store.connect(database, write=True) as db:
                store.register(db, "synthetic")
            for current in (expected, {**expected, "consent_to_history_and_analysis": True},
                            {**expected, "consent_to_history_and_analysis": False}):
                with patch("research.key_listener.load", return_value=current):
                    self.assertTrue(selection_ready(directory, database, expected))
            with store.connect(database, write=True) as db:
                db.execute("UPDATE subjects SET active=0")
            with patch("research.key_listener.load", return_value=expected):
                self.assertFalse(selection_ready(directory, database, expected))

    def test_request_deadline_honors_both_backoffs_without_resetting_saved_deadline(self):
        with patch("research.key_listener.auth_cooldown.active", return_value={"seconds_remaining": 900}), \
             patch("research.key_listener.searchparty_backoff.active", return_value={"seconds_remaining": 1500}):
            self.assertEqual(next_request_allowed(Path("synthetic"), 1000, 2000), 2500)
            self.assertEqual(next_request_allowed(Path("synthetic"), 1000, 5000), 5000)

    def test_changed_selection_stops_without_opening_a_database(self):
        expected = {"alias": "synthetic"}
        with patch("research.key_listener.load", return_value={**expected, "alias": "changed"}), \
             patch("research.key_listener.store.connect") as database:
            self.assertFalse(selection_ready(Path("synthetic"), Path("db.sqlite"), expected))
            database.assert_not_called()


@unittest.skipIf(save_delivery is None, "Optional protocol/auth dependencies")
class ListenerProtocolTests(unittest.TestCase):
    def test_transient_outage_recovers_after_three_failures_without_new_login(self):
        from anyio import EndOfStream
        from research.key_listener import run
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            now, waits, attempts = [1000.0], [], []
            async def sleep(seconds):
                waits.append(seconds)
                now[0] += seconds
            async def acquire(*args, **kwargs):
                attempts.append(kwargs["listen_only"])
                if len(attempts) <= 3:
                    raise EndOfStream()
                return {"people_key_received": True}
            clock = SimpleNamespace(time=lambda: now[0], monotonic=lambda: now[0])
            with patch("research.key_listener.time", clock), \
                 patch("research.key_listener.load", return_value={}), \
                 patch("research.key_listener.selection_ready", return_value=True), \
                 patch("research.key_listener.auth_cooldown.active", return_value=None), \
                 patch("research.key_listener.searchparty_backoff.active", return_value=None), \
                 patch("research.key_listener.asyncio.sleep", side_effect=sleep), \
                 patch("research.key_probe.acquire", side_effect=acquire):
                result = asyncio.run(run(directory, duration=3600, stop_after_key=True))
            self.assertEqual(attempts, [True] * 4)
            self.assertEqual(waits, [120, 240, 300])
            self.assertTrue(result["people_key_received"])

    def test_verified_key_rotation_is_atomic_and_preserves_only_one_previous_key(self):
        def delivery(marker):
            key = ec.generate_private_key(ec.SECP224R1())
            raw = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            raw += key.private_numbers().private_value.to_bytes(28, "big")
            return SimpleNamespace(private_key_blob=raw, advertised_id=base64.b64encode(bytes([marker]) * 32).decode())
        selected = {"account_dsid": "1", "relationship": {"fm_id": "synthetic"}}
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            saved = {"selected-person.dpapi": selected}
            def read(path):
                return saved[path.name]
            def write(path, value):
                saved[path.name] = value
                path.write_bytes(b"synthetic ciphertext")
            with patch("research.key_probe.load", side_effect=read), \
                 patch("research.key_probe.save_new", side_effect=write), \
                 patch("research.key_probe.save_atomic", side_effect=write):
                first, second = delivery(1), delivery(2)
                self.assertTrue(save_delivery(directory, selected, first, dsid="1", device_id="this", replace_existing=True))
                self.assertFalse(save_delivery(directory, selected, first, dsid="1", device_id="this", replace_existing=True))
                self.assertTrue(save_delivery(directory, selected, second, dsid="1", device_id="this", replace_existing=True))
                self.assertEqual(saved["previous-people-key.dpapi"]["advertised_id"], first.advertised_id)
                self.assertEqual(saved["people-key.dpapi"]["advertised_id"], second.advertised_id)
                with self.assertRaises(ValueError):
                    save_delivery(directory, selected, delivery(2), dsid="1", device_id="this", replace_existing=True)
                saved["selected-person.dpapi"] = {**selected, "relationship": {"fm_id": "different-participant"}}
                with self.assertRaises(ValueError):
                    save_delivery(directory, selected, delivery(3), dsid="1", device_id="this", replace_existing=True)

    def test_bootstrap_deadline_is_saved_before_network_and_stops_after_key(self):
        from research.key_listener import run
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            status_path = directory / "key-listener-status.json"
            async def successful(*args, **kwargs):
                self.assertGreater(json.loads(status_path.read_text())["next_request_unix"], 0)
                self.assertFalse(kwargs["listen_only"])
                self.assertTrue(kwargs["receive_updates"])
                return {"people_key_received": True}
            with patch("research.key_listener.load", return_value={}), \
                 patch("research.key_listener.selection_ready", return_value=True), \
                 patch("research.key_listener.auth_cooldown.active", return_value=None), \
                 patch("research.key_listener.searchparty_backoff.active", return_value=None), \
                 patch("research.key_probe.acquire", side_effect=successful) as acquire:
                result = asyncio.run(run(directory, duration=20, request_missing=True, stop_after_key=True))
            self.assertTrue(result["people_key_received"])
            acquire.assert_awaited_once()
