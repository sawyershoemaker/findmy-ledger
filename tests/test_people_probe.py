import contextlib
import copy
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

try:
    from findmy import LoginState
    from research.fmf_client import FriendsClient, FriendsError, checked_host, find_host, following
    from research.saved_session import validate_session
    from research.people_probe import select_person
    from research.windows_secrets import load, save_new
except ImportError:
    LoginState = None


@unittest.skipIf(LoginState is None, "Install the auth extra")
class PeopleTests(unittest.TestCase):
    def test_service_hosts_reject_foreign_destinations_and_embedded_credentials(self):
        for host in ["https://example.invalid", "https://p01-fmfmobile.icloud.com.evil.invalid",
                     "https://user:pass@p01-fmfmobile.icloud.com", "http://p01-fmfmobile.icloud.com",
                     "https://p01-fmfmobile.icloud.com:444"]:
            with self.subTest(host=host), self.assertRaises(FriendsError):
                checked_host(host)
        self.assertEqual(checked_host("https://p139-fmfmobile.icloud.com/ignored"), "p139-fmfmobile.icloud.com")

    def test_service_host_discovery_is_unambiguous(self):
        self.assertEqual(find_host({"tokens": {"mmeFMFAppToken": "synthetic"}}), "p01-fmfmobile.icloud.com")
        self.assertEqual(find_host({"nested": {"host": "p139-fmfmobile.icloud.com"}}), "p139-fmfmobile.icloud.com")
        with self.assertRaises(FriendsError):
            find_host({"hosts": ["p139-fmfmobile.icloud.com", "p140-fmfmobile.icloud.com"]})

    def test_following_uses_accepted_handles_and_expiry_not_ambiguous_optout_flag(self):
        base = {"id": "synthetic-id", "invitationAcceptedHandles": ["person@example.invalid"],
                "secureLocationsCapable": True, "fallbackToLegacyAllowed": False}
        rows = [base, {**base, "id": "accepted-with-flag", "optedNotToShare": True},
                {**base, "id": "expired", "expires": 999_000},
                {**base, "id": "expired-ms", "expires": 1_800_000_000_000},
                {**base, "id": "invitation", "invitationAcceptedHandles": []}, base]
        result = following({"following": rows, "locations": [{"latitude": 99}]}, now=1_900_000_000)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["fm_id"], "synthetic-id")
        self.assertEqual(result[1]["fm_id"], "accepted-with-flag")
        self.assertNotIn("locations", result[0])

    def test_location_fields_are_never_cached_with_relationships(self):
        result = following({"following": [{"id": "synthetic", "invitationAcceptedHandles": ["a@example.invalid"],
                                          "location": {"latitude": 12.34}, "unexpectedToken": "synthetic-secret"}]})
        self.assertNotIn("latitude", str(result))
        self.assertNotIn("synthetic-secret", str(result))

    def test_restored_session_must_match_machine_and_have_no_password(self):
        identity = {"local_user_uuid": "synthetic-user", "device_id": "synthetic-device"}
        state = {"type": "account", "anisette": {"type": "aniMacEmulated"},
                 "ids": {"uid": "synthetic-user", "devid": "synthetic-device"},
                 "account": {"password": None}, "login": {"state": LoginState.LOGGED_IN.value,
                     "data": {"dsid": "123456", "mobileme_data": {"tokens": {"mmeFMFAppToken": "synthetic-token"}}}}}
        validate_session(state, identity)
        bad = copy.deepcopy(state)
        bad["ids"]["devid"] = "another-machine"
        with self.assertRaises(ValueError):
            validate_session(bad, identity)
        bad = copy.deepcopy(state)
        bad["account"]["password"] = "synthetic-password"
        with self.assertRaises(ValueError):
            validate_session(bad, identity)

    @unittest.skipUnless(os.name == "nt", "DPAPI requires Windows")
    def test_local_selection_saves_only_chosen_relationship_and_redacts_status(self):
        import time
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            rows = [{"fm_id": f"synthetic-{i}", "handles": [f"person{i}@example.invalid"],
                     "secure_locations_capable": True, "legacy_fallback_allowed": False} for i in range(2)]
            save_new(directory / "people-list.dpapi", {"created_at": time.time(), "account_dsid": "123456", "relationships": rows})
            with patch("research.people_probe.sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="2"), \
                 contextlib.redirect_stdout(io.StringIO()):
                result = select_person(directory)
            saved = load(directory / "selected-person.dpapi")
            self.assertEqual(saved["relationship"]["fm_id"], "synthetic-1")
            self.assertNotIn("consent_to_history_and_analysis", saved)
            self.assertNotIn("synthetic-0", str(saved))
            self.assertNotIn("example.invalid", str(result))
            self.assertNotIn(b"person1", (directory / "selected-person.dpapi").read_bytes())
            with patch("builtins.input") as prompt:
                self.assertTrue(select_person(directory)["already_selected"])
                prompt.assert_not_called()


@unittest.skipIf(LoginState is None, "Install the auth extra")
class FriendsSequenceTests(unittest.IsolatedAsyncioTestCase):
    def client(self, responses, *, native_context=False, token="synthetic-mobileme"):
        state = {"account": {"username": "receiver@example.invalid"}, "login": {"data": {
            "dsid": "123456", "mobileme_data": {"tokens": {"mmeFMFAppToken": "synthetic-fmf", "mmeAuthToken": token}}}}}
        provider = SimpleNamespace(account_ids={"devid": "synthetic-device", "uid": "synthetic-user"},
            client="<MacBookPro13,2> <macOS;13.1;22C65>", get_headers=AsyncMock(return_value={}), close=AsyncMock())
        session = MagicMock()
        replies = []
        for body, version in responses:
            reply = SimpleNamespace(status=200, headers={"X-FMF-Model-Version": version},
                                    read=AsyncMock(return_value=json.dumps(body).encode()))
            manager = MagicMock()
            manager.__aenter__ = AsyncMock(return_value=reply)
            manager.__aexit__ = AsyncMock(return_value=False)
            replies.append(manager)
        session.post.side_effect = replies
        transport = SimpleNamespace(_ssl=object(), _get_session=AsyncMock(return_value=session), close=AsyncMock())
        with patch("research.fmf_client.AuthenticationSession", return_value=transport):
            client = FriendsClient(state, provider, None, apns_token="AB" * 32, native_context=native_context)
        return client, session

    async def test_selected_refresh_carries_server_state_across_delta_and_model_versions(self):
        server = {"clientId": "synthetic-server-id", "prsId": 123456}
        data = {"followingVersion": 7}
        client, session = self.client([({"serverContext": server, "dataContext": data}, "8"), ({}, "9"), ({}, "9")])
        await client.request()
        await client.request(refresh=True)
        await client.request(selected="selected-synthetic")
        calls = session.post.call_args_list
        self.assertTrue(calls[0].args[0].endswith("/initClient"))
        self.assertTrue(calls[1].args[0].endswith("/minCallback/refreshClient"))
        self.assertTrue(calls[2].args[0].endswith("/minCallback/selFriend/refreshClient"))
        for index, model in ((1, "8"), (2, "9")):
            request = calls[index].kwargs
            self.assertEqual(request["json"]["serverContext"], server)
            self.assertEqual(request["json"]["dataContext"], data)
            self.assertEqual(request["headers"]["X-FMF-Model-Version"], model)
            self.assertFalse(request["allow_redirects"])
            self.assertNotIn("authToken", request["json"]["serverContext"])
        self.assertEqual(calls[2].kwargs["json"]["clientContext"]["selectedFriend"], "selected-synthetic")
        self.assertEqual(calls[2].kwargs["json"]["clientContext"]["apsToken"], "AB" * 32)
        self.assertEqual(calls[2].kwargs["json"]["clientContext"]["appName"], "fmfd")
        self.assertNotIn("callerHandleId", calls[2].kwargs["json"]["clientContext"])
        await client.close()

    async def test_friends_rejection_exposes_only_status_for_collector_backoff(self):
        from research.auth_diagnostics import AuthTrace
        for status in (401, 429):
            with self.subTest(status=status):
                client, session = self.client([])
                client.trace = AuthTrace()
                session.post.side_effect = None
                response = SimpleNamespace(status=status, headers={"Retry-After": "120"}, read=AsyncMock())
                session.post.return_value.__aenter__.return_value = response
                with self.assertRaises(FriendsError):
                    await client.request()
                self.assertEqual(client.trace.http_status, status)
                self.assertEqual(client.trace.retry_after_seconds, 120 if status == 429 else None)
                session.post.assert_called_once()
                response.read.assert_not_awaited()
                await client.close()

    async def test_native_context_is_explicit_and_does_not_change_http_auth_or_server_state(self):
        import base64
        client, session = self.client([({"serverContext": {"clientId": "synthetic-server"}}, "1"), ({}, "1")], native_context=True)
        await client.request()
        await client.request(refresh=True)
        request = session.post.call_args.kwargs
        self.assertEqual(request["json"]["serverContext"], {"clientId": "synthetic-server", "prsId": "123456",
            "authToken": base64.b64encode(b"synthetic-mobileme").decode()})
        self.assertEqual(request["auth"].password, "synthetic-fmf")
        self.assertEqual(request["json"]["clientContext"]["appName"], "findmylocated")
        self.assertEqual(request["json"]["clientContext"]["callerHandleId"], "receiver@example.invalid")
        self.assertEqual(request["json"]["clientContext"]["contextBundleApp"], "com.apple.findmy.findmylocated")
        self.assertEqual(client.server_context, {"clientId": "synthetic-server"})
        await client.close()

    async def test_missing_native_token_and_malformed_server_context_stop(self):
        client, session = self.client([], native_context=True, token=None)
        with self.assertRaises(FriendsError):
            await client.request()
        session.post.assert_not_called()
        await client.close()
        client, session = self.client([({"serverContext": "invalid-synthetic"}, "1")])
        with self.assertRaises(FriendsError):
            await client.request()
        session.post.assert_called_once()
        await client.close()
