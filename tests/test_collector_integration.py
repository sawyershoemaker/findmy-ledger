"""Synthetic end-to-end collector exercise; no Apple requests or real participant data."""
import asyncio
import base64
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from location_ledger import store
from research import collector
from research.windows_secrets import load, save_atomic

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from research.key_probe import save_delivery
except ImportError:
    save_delivery = None


@unittest.skipUnless(os.name == "nt" and save_delivery is not None, "Windows DPAPI and optional protocol dependencies")
class CollectorIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_rotation_delayed_ingestion_duplicate_and_pause_in_one_run(self):
        now = [1793217600.0]
        first_time = int(now[0]) - 30
        delayed_time = int(now[0]) - 1800
        fm_id, dsid, device = "synthetic-selected", "synthetic-account", "synthetic-receiver"
        keys = [ec.generate_private_key(ec.SECP224R1()) for _ in range(2)]
        ids = [base64.b64encode(bytes([i + 1]) * 32).decode() for i in range(2)]

        def key_blob(key):
            return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint) + key.private_numbers().private_value.to_bytes(28, "big")

        def response(index, stamp):
            sender = ec.generate_private_key(ec.SECP224R1())
            point = sender.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            shared = sender.exchange(ec.ECDH(), keys[index].public_key())
            material = hashlib.sha256(shared + b"\0\0\0\1" + point).digest()
            plain = json.dumps({"findMyId": fm_id, "latitude": 40, "longitude": -75,
                "horizontalAccuracy": 12, "timestamp": stamp - 978307200}).encode()
            sealed = point + AESGCM(material[:16]).encrypt(material[16:], plain, None)
            return {"statusCode": "200", "locationPayload": [{"id": ids[index], "locationInfo": [
                {"fmt": 0, "location": base64.b64encode(sealed).decode()}]}]}

        selection = {"alias": "participant",
            "account_dsid": dsid, "relationship": {"fm_id": fm_id}}
        client = SimpleNamespace(login={"dsid": dsid}, device_id=device, close=AsyncMock(),
            request=AsyncMock(return_value={"following": [{"id": fm_id, "invitationAcceptedHandles": ["synthetic@example.invalid"]}]}))
        provider = SimpleNamespace(account_ids={"devid": device})
        state = {"login": {"data": {"dsid": dsid}}}
        original_poll, original_sleep = collector.poll, asyncio.sleep
        rotation_requested, rotated = asyncio.Event(), asyncio.Event()
        requests, observed_statuses = [], []

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = root / "history.sqlite"
            store.initialize(database)
            with store.connect(database, write=True) as db:
                store.register(db, "participant")
            for name in ("apple-session.dpapi", "mac-machine.dpapi", "ids.dpapi"):
                save_atomic(root / name, {"fixture": "synthetic"})
            save_atomic(root / "selected-person.dpapi", selection)
            save_atomic(root / "apns.dpapi", {"device_id": device, "courier_token": "ab" * 32})
            save_delivery(root, selection, SimpleNamespace(advertised_id=ids[0], private_key_blob=key_blob(keys[0])),
                          dsid=dsid, device_id=device)
            save_atomic(root / "latest-fix.dpapi", {"account_dsid": dsid, "fm_id": fm_id,
                "observation": {"source": "findmy-people", "observed_at": first_time}})

            async def fetch(*args, **kwargs):
                requests.append(kwargs["advertised_id"])
                if len(requests) == 1:
                    rotation_requested.set()
                    await rotated.wait()
                    return response(0, first_time)
                if len(requests) == 2:
                    return response(1, first_time)
                return response(1, delayed_time)

            async def receive(*args, **kwargs):
                kwargs["ready_event"].set()
                await rotation_requested.wait()
                save_delivery(root, selection, SimpleNamespace(advertised_id=ids[1], private_key_blob=key_blob(keys[1])),
                              dsid=dsid, device_id=device, replace_existing=True)
                rotated.set()
                await asyncio.Event().wait()

            async def poll(*args):
                result = await original_poll(*args)
                observed_statuses.append(result)
                if len(observed_statuses) == 3:
                    with store.connect(database, write=True) as db:
                        db.execute("UPDATE subjects SET active=0 WHERE alias='participant'")
                return result

            async def sleep(seconds):
                now[0] += seconds
                await original_sleep(0)

            fake_async = SimpleNamespace(**{name: getattr(asyncio, name) for name in dir(asyncio) if not name.startswith("__")})
            fake_async.sleep = sleep
            with patch("research.saved_session.restore", return_value=(state, provider)), \
                 patch("research.location_probe.restore", return_value=(state, provider)), \
                 patch("research.location_probe.FriendsClient", return_value=client), \
                 patch("research.location_probe.searchparty", side_effect=fetch), \
                 patch("research.location_probe.time", SimpleNamespace(time=lambda: now[0])), \
                 patch("research.collector.time", SimpleNamespace(time=lambda: now[0])), \
                 patch("research.collector.asyncio", fake_async), \
                 patch("research.collector.poll", side_effect=poll), \
                 patch("research.key_listener.run", side_effect=receive):
                result = await asyncio.wait_for(collector.serve(root, database, max_polls=5), timeout=5)

            self.assertEqual(requests, [ids[0], ids[1], ids[1]])
            self.assertEqual([r["new_observation"] for r in observed_statuses], [True, False, True])
            self.assertFalse(observed_statuses[-1]["fresh_report_received"])
            self.assertEqual(observed_statuses[-1]["source_observed_at_utc"], store.iso(delayed_time))
            self.assertEqual(result["reason"], "participant_paused")
            self.assertEqual(result["state"], "paused")
            self.assertFalse(result["live_collection_ready"])
            self.assertEqual(load(root / "previous-people-key.dpapi")["advertised_id"], ids[0])
            self.assertEqual(load(root / "people-key.dpapi")["advertised_id"], ids[1])
            with store.connect(database) as db:
                self.assertEqual([r[0] for r in db.execute("SELECT observed_at FROM samples ORDER BY observed_at")], [delayed_time, first_time])
                self.assertFalse(store.subject(db, "participant")["active"])
