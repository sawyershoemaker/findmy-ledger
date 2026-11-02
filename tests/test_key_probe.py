import asyncio
import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

try:
    from pypush.apns.protocol import SendMessageCommand
    from research.key_probe import selected_relationship, searchparty_summary
    from research.push_receiver import Receiver
except ImportError:
    SendMessageCommand = None


@unittest.skipIf(SendMessageCommand is None, "Install the push-research extra")
class KeySelectionTests(unittest.TestCase):
    def test_key_rejection_categories_do_not_expose_unrecognized_details(self):
        from research.key_probe import key_rejection_category
        self.assertEqual(key_rejection_category("NGM validator mismatch"), "ngm_identity_binding")
        self.assertEqual(key_rejection_category("IDS sender does not match selected relationship"), "other_sender")
        for detail in (None, {}, ["private"], "NGM validator mismatch private@example.invalid",
                       "secret-token-value", "a" * 300):
            self.assertEqual(key_rejection_category(detail), "unclassified")

    def test_saved_key_requires_current_device_selection_and_verified_sender(self):
        import base64
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from research.key_probe import validate_saved_key
        private = ec.generate_private_key(ec.SECP224R1())
        public = private.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        blob = public + private.private_numbers().private_value.to_bytes(28, "big")
        selection = {"account_dsid": "123456",
                     "relationship": {"fm_id": "selected"}}
        saved = {"account_dsid": "123456", "fm_id": "selected", "device_id": "synthetic-device",
                 "sender_authenticated": True, "advertised_id": base64.b64encode(b"a" * 32).decode(),
                 "private_key_blob": base64.b64encode(blob).decode()}
        decoded = validate_saved_key(saved, selection, dsid="123456", device_id="synthetic-device")
        self.assertEqual(decoded.private_numbers().private_value, private.private_numbers().private_value)
        for change in ({"device_id": "different-device"}, {"fm_id": "different-person"},
                       {"account_dsid": "different-account"}, {"sender_authenticated": False},
                       {"sender_authenticated": None}, {"advertised_id": "invalid"},
                       {"private_key_blob": base64.b64encode(b"invalid-key").decode()}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_saved_key({**saved, **change}, selection, dsid="123456", device_id="synthetic-device")
        with self.assertRaises(ValueError):
            validate_saved_key(saved, {**selection, "account_dsid": "different-account"},
                               dsid="123456", device_id="synthetic-device")

    def test_failed_participants_are_reported_as_counts_and_a_selected_boolean(self):
        import json
        result = searchparty_summary({"statusCode": "200", "failedFmIds": ["synthetic-private-selected"]},
                                     selected_id="synthetic-private-selected")
        self.assertEqual(result["failed_participant_count"], 1)
        self.assertTrue(result["selected_participant_failed"])
        self.assertNotIn("synthetic-private", json.dumps(result))

    def test_searchparty_diagnostics_keep_nested_failure_codes_without_sensitive_fields(self):
        import json
        reply = {"statusCode": "200", "configVersion": 1, "locationPayload": [],
                 "results": [{"statusCode": "403", "fmId": "synthetic-private-person"},
                             {"status": 200, "location": "synthetic-private-ciphertext"}],
                 "synthetic-private-key": "synthetic-private-value"}
        result = searchparty_summary(reply)
        self.assertEqual(result["results_statuses"], [403, 200])
        self.assertEqual(result["locationPayload_count"], 0)
        self.assertEqual(result["other_field_count"], 1)
        self.assertNotIn("synthetic-private", json.dumps(result))

    def test_only_current_selected_relationship_is_eligible(self):
        selection = {"account_dsid": "123456",
                     "relationship": {"fm_id": "selected"}}
        rows = [{"fm_id": key, "handles": [key + "@example.invalid"],
                 "secure_locations_capable": True, "legacy_fallback_allowed": False}
                for key in ("other", "selected")]
        selected = selected_relationship(selection, "123456", rows)
        self.assertEqual(selected.fm_id, "selected")
        self.assertEqual(selected.accepted_handles, ("selected@example.invalid",))
        for changed_selection, dsid, current in ((selection, "different-account", rows),
                ({**selection, "account_dsid": "different-account"}, "123456", rows),
                (selection, "123456", rows[:1]), (selection, "123456", rows + rows[1:])):
            with self.assertRaises(ValueError):
                selected_relationship(changed_selection, dsid, current)


@unittest.skipIf(SendMessageCommand is None, "Install the push-research extra")
class PushReceiverTests(unittest.IsolatedAsyncioTestCase):
    async def test_pending_key_remains_queued_during_receiver_directory_preflight(self):
        from research.key_subscription import subscribed_acquirer_class
        commands = AsyncMock()
        receiver = Receiver(commands, b"t" * 32)
        topic = "com.apple.private.alloy.fmd"
        class BaseAcquirer:
            async def _run_receiver_preflight(self, connection, base_token):
                async with connection.notification_stream(topic, base_token) as directory:
                    for queue in connection.subscriptions[topic]:
                        queue.put_nowait(b"synthetic pending key")
                    # A directory query consumes/ignores the unrelated message.
                    await directory.receive()
        acquirer = subscribed_acquirer_class(SimpleNamespace(PeopleKeyAcquirer=BaseAcquirer))()
        await acquirer._run_receiver_preflight(receiver, b"t" * 32)
        commands.send.assert_not_called()
        async with receiver.notification_stream(topic) as keys:
            await acquirer.finish_receiver_preflight()
            self.assertEqual(await asyncio.wait_for(keys.receive(), 1), b"synthetic pending key")

    def http_client(self, body, *, status=200, retry_after=None):
        from research.auth_diagnostics import AuthTrace
        class Content:
            async def iter_chunked(self, size):
                yield body[:5]
                yield body[5:]
        reply = SimpleNamespace(status=status, content=Content(), headers={} if retry_after is None else {"Retry-After": retry_after})
        manager = MagicMock()
        manager.__aenter__ = AsyncMock(return_value=reply)
        manager.__aexit__ = AsyncMock(return_value=False)
        session = MagicMock()
        session.post.return_value = manager
        provider = SimpleNamespace(account_ids={"uid": "synthetic-user"}, get_headers=AsyncMock(return_value={}))
        client = SimpleNamespace(provider=provider, device_id="synthetic-device", product="SyntheticMac", os_version="13.1", build="22C65",
            apns_token="AB" * 32, login={"dsid": "123456", "mobileme_data": {"tokens": {"searchPartyToken": "synthetic-token"}}},
            http=SimpleNamespace(trace=AuthTrace(), _ssl=object(), _get_session=AsyncMock(return_value=session)))
        return client, session

    async def test_http_success_with_failed_selected_id_is_not_key_request_success(self):
        from research.key_probe import searchparty
        from research.searchparty_backoff import SearchPartyError
        client, session = self.http_client(json.dumps({"statusCode": "200", "failedFmIds": ["selected"]}).encode())
        stats = {}
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(SearchPartyError):
            await searchparty(client, "selected", state_dir=directory, stats=stats)
        self.assertTrue(stats["selected_participant_failed"])
        request = session.post.call_args.kwargs
        self.assertEqual(request["headers"]["accept-version"], "1")
        self.assertEqual(request["json"]["fetch"], [{"fmId": "selected", "intent": "distributeKeys", "mode": "proactive", "ids": []}])
        self.assertEqual(request["json"]["clientContext"], {
            "apsToken": "AB" * 32, "clientId": "synthetic-device",
            "contextApp": "com.apple.findmy.findmylocated", "shallowStats": {}, "liveStats": {},
            "nearbyWatchIdentifiers": []})
        self.assertFalse(request["allow_redirects"])

    async def test_503_creates_guard_before_a_second_network_attempt(self):
        from research.key_probe import searchparty
        from research.searchparty_backoff import SearchPartyError, active
        client, session = self.http_client(b"private-response-body", status=503, retry_after="1727")
        stats = {}
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(SearchPartyError):
                await searchparty(client, "selected", state_dir=directory, stats=stats)
            self.assertIsNotNone(active(directory))
            with self.assertRaises(SearchPartyError):
                await searchparty(client, "selected", state_dir=directory)
            session.post.assert_called_once()
            client.provider.get_headers.assert_awaited_once()
            self.assertFalse((Path(directory) / "auth-cooldown.json").exists())
        self.assertEqual(stats["retry_after_seconds"], 1727)
        self.assertEqual(stats["response_bytes"], len(b"private-response-body"))
        self.assertEqual(stats["response_format"], "other")
        self.assertNotIn("private", json.dumps(stats))

    async def test_rejection_diagnostics_identify_format_without_capturing_values(self):
        from research.key_probe import searchparty
        from research.searchparty_backoff import SearchPartyError
        for body, expected in ((b'<html>503 Service Temporarily Unavailable private@example.invalid secret</html>', "html"),
                (b'{"statusCode":"503","private":"secret"}', "json")):
            client, session = self.http_client(body, status=503)
            stats = {}
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(SearchPartyError):
                await searchparty(client, "selected", state_dir=directory, stats=stats)
            self.assertEqual(stats["response_format"], expected)
            self.assertNotIn("private", json.dumps(stats))
            self.assertNotIn("secret", json.dumps(stats))
            if expected == "json":
                self.assertEqual(stats["service_status"], 503)
            else:
                self.assertEqual(stats["error_page_categories"], ["service_unavailable"])

    async def test_gateway_preserves_opaque_receiver_id_and_records_bootstrap_attempt(self):
        from research.key_probe import searchparty
        client, session = self.http_client(json.dumps({"statusCode": "200", "locationPayload": []}).encode())
        client.device_id = "SYNTHETIC-MixedCase"
        with tempfile.TemporaryDirectory() as directory:
            await searchparty(client, "selected", state_dir=directory)
            saved = json.loads((Path(directory) / "key-request-status.json").read_text())
        self.assertEqual(session.post.call_args.kwargs["json"]["clientContext"]["clientId"], client.device_id)
        self.assertEqual(saved["next_bootstrap_request_unix"] - saved["request_started_unix"], 1800)
        self.assertNotIn(client.device_id, json.dumps(saved))

    async def test_listen_only_checks_relationship_without_requesting_distribution(self):
        from types import SimpleNamespace
        from research.key_probe import prepare_key_request
        from research.auth_diagnostics import AuthTrace
        selected = {"account_dsid": "123456",
                    "relationship": {"fm_id": "selected"}}
        response = {"following": [{"id": "selected", "invitationAcceptedHandles": ["participant@example.invalid"],
                                  "secureLocationsCapable": True, "fallbackToLegacyAllowed": False}]}
        client = SimpleNamespace(request=AsyncMock(return_value=response))
        stats = {}
        with patch("research.key_probe.searchparty", new=AsyncMock()) as fetch:
            result = await prepare_key_request(client, selected, "123456", "unused", AuthTrace(), stats, listen_only=True)
        self.assertEqual(result.fm_id, "selected")
        client.request.assert_awaited_once_with()
        fetch.assert_not_awaited()
        self.assertFalse(stats["key_distribution_requested"])
        self.assertTrue(stats["selected_relationship_current"])

    async def test_gateway_503_keeps_receiver_eligible_for_already_queued_key(self):
        from research.key_probe import prepare_key_request
        from research.auth_diagnostics import AuthTrace
        from research.searchparty_backoff import SearchPartyError
        selected = {"account_dsid": "1", "relationship": {"fm_id": "selected"}}
        client = SimpleNamespace(request=AsyncMock(return_value={"following": [
            {"id": "selected", "invitationAcceptedHandles": ["synthetic@example.invalid"]}]}))
        async def reject(*args, **kwargs):
            kwargs["stats"].update(http_status=503, retry_after_seconds=120)
            raise SearchPartyError("synthetic service rejection")
        stats = {}
        with tempfile.TemporaryDirectory() as directory, patch("research.key_probe.searchparty", side_effect=reject):
            relationship = await prepare_key_request(client, selected, "1", directory, AuthTrace(), stats)
        self.assertEqual(relationship.fm_id, "selected")
        self.assertFalse(stats["key_distribution_request_accepted"])
        self.assertTrue(stats["receiving_despite_gateway_rejection"])

    async def test_apns_alpn_uses_private_context_and_cannot_mutate_https_context(self):
        from research.apns_probe import connect
        context = MagicMock()
        with patch("research.ids_tls.new_trust_context", return_value=context) as private, \
             patch("research.ids_tls.trust_context") as shared, \
             patch("anyio.connect_tcp", AsyncMock(side_effect=ConnectionError("synthetic failure"))) as tcp:
            with self.assertRaises(ConnectionError):
                await connect(None, None)
        private.assert_called_once_with()
        shared.assert_not_called()
        context.set_alpn_protocols.assert_called_once_with(["apns-security-v3"])
        self.assertIs(tcp.call_args.kwargs["ssl_context"], context)
        self.assertEqual(tcp.call_args.kwargs["tls_hostname"], "courier.push.apple.com")

    async def test_topic_and_token_isolation_and_subscription_cleanup(self):
        incoming = asyncio.Queue()
        commands = AsyncMock()
        commands.receive.side_effect = incoming.get
        receiver = Receiver(commands, b"t" * 32)
        topic = "com.apple.private.alloy.fmf"
        task = asyncio.create_task(receiver.pump())
        try:
            async with receiver.notification_stream(topic) as stream:
                for message_topic, token, payload in (("com.apple.private.ids", b"t" * 32, b"wrong-topic"),
                        (topic, b"x" * 32, b"wrong-token"), (topic, b"t" * 32, b"synthetic-accepted")):
                    await incoming.put(SendMessageCommand(payload=payload, id=b"1234", topic=message_topic,
                                                           token=token, outgoing=False))
                item = await asyncio.wait_for(stream.receive(), 1)
                self.assertEqual(item.payload, b"synthetic-accepted")
                self.assertTrue(stream.queue.empty())
            self.assertEqual(receiver.subscriptions, {})
            self.assertEqual(commands.send.call_args.args[0].enabled_topic_hashes, [])
            self.assertEqual(receiver.stats["notification_packets"], 3)
            self.assertEqual(receiver.stats["notifications_for_other_token"], 1)
            self.assertEqual(receiver.stats["notifications_without_subscription"], 1)
            self.assertEqual(receiver.stats["notifications_queued"], 1)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_transport_failure_reaches_waiter_without_reconnect(self):
        commands = AsyncMock()
        commands.receive.side_effect = ConnectionError("synthetic failure")
        receiver = Receiver(commands, b"t" * 32)
        async with receiver.notification_stream("com.apple.private.ids") as stream:
            await receiver.pump()
            with self.assertRaises(ConnectionError):
                await stream.receive()
            with self.assertRaises(ConnectionError):
                await receiver._send(object())
        commands.receive.assert_called_once()

    async def test_transport_acknowledges_unhandled_packets_and_redelivery_once_per_receipt(self):
        from pypush.apns.protocol import SendMessageAck
        incoming = asyncio.Queue()
        commands = AsyncMock()
        commands.receive.side_effect = incoming.get
        receiver = Receiver(commands, b"t" * 32)
        message = SendMessageCommand(payload=b"unverified synthetic application payload", id=b"1234",
                                     topic="com.apple.findmy", token=b"t" * 32, outgoing=False)
        task = asyncio.create_task(receiver.pump())
        try:
            await incoming.put(message)
            for _ in range(10):
                await asyncio.sleep(0)
                if receiver.stats.get("transport_acks"):
                    break
            self.assertEqual(receiver.stats["notifications_without_subscription"], 1)
            self.assertEqual(receiver.stats["transport_acks"], 1)
            await receiver.ack(message)
            self.assertEqual(receiver.stats["transport_acks"], 1)
            await incoming.put(message)
            for _ in range(10):
                await asyncio.sleep(0)
                if receiver.stats["transport_acks"] == 2:
                    break
            self.assertEqual(receiver.stats["transport_acks"], 2)
            self.assertTrue(all(isinstance(call.args[0], SendMessageAck) for call in commands.send.call_args_list))
            self.assertEqual(receiver.subscriptions, {})
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_wrong_subscription_token_is_rejected_before_sending(self):
        commands = AsyncMock()
        receiver = Receiver(commands, b"t" * 32)
        with self.assertRaises(ValueError):
            async with receiver.notification_stream("com.apple.private.ids", b"x" * 32):
                pass
        commands.send.assert_not_called()
