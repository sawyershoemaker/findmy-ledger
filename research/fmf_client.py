"""Bounded read-only Friends protocol adapter. Never logs response bodies.

Protocol references: Onitrack 04dd253 and RustPush 82dc6f8, linked in docs/research.md.
Only init/refresh are supported; no invitation, sharing, fence, or device actions.
"""
import base64
import os
import re
import time
from urllib.parse import quote, urlsplit

from aiohttp import BasicAuth

from .auth_transport import AuthenticationSession


class FriendsError(Exception):
    def __init__(self, category):
        self.category = category
        super().__init__(category)


def checked_host(value):
    if not isinstance(value, str):
        raise FriendsError("invalid_service_host")
    target = urlsplit(value if "://" in value else "https://" + value)
    if (target.scheme != "https" or target.username or target.password or target.port not in (None, 443)
            or not re.fullmatch(r"(?:p[0-9]{1,3}-)?fmfmobile\.icloud\.com", target.hostname or "")):
        raise FriendsError("invalid_service_host")
    return target.hostname


def find_host(data):
    candidates = set()

    def visit(value):
        if isinstance(value, dict):
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
        elif isinstance(value, str) and "fmfmobile.icloud.com" in value:
            candidates.add(checked_host(value))

    visit(data)
    if len(candidates) > 1:
        raise FriendsError("ambiguous_service_host")
    return next(iter(candidates), "p01-fmfmobile.icloud.com")


def following(response, *, now=None):
    """Keep accepted, unexpired following entries, never embedded locations.

    optedNotToShare is also present on usable incoming shares; it is not a
    validated revocation signal. A selected share must remain in following.
    """
    now = time.time() if now is None else now
    rows = response.get("following")
    if not isinstance(rows, list):
        raise FriendsError("missing_relationship_list")
    result = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = row.get("id") or row.get("fmId")
        handles = row.get("invitationAcceptedHandles")
        if not isinstance(key, str) or not key or not isinstance(handles, list):
            continue
        handles = [h for h in handles if isinstance(h, str) and h]
        if not handles or key in seen:
            continue
        expires = row.get("expires")
        if type(expires) in (int, float) and expires > 0:
            expiry_seconds = expires / 1000 if expires > 100_000_000_000 else expires
            if expiry_seconds <= now:
                continue
        seen.add(key)
        result.append({"fm_id": key, "handles": handles,
                       "secure_locations_capable": row.get("secureLocationsCapable") if type(row.get("secureLocationsCapable")) is bool else None,
                       "legacy_fallback_allowed": row.get("fallbackToLegacyAllowed") if type(row.get("fallbackToLegacyAllowed")) is bool else None})
    return result


def relationship_shape(response):
    """Counts and booleans only, used to diagnose a list that cannot be selected."""
    rows = response.get("following", [])
    rows = [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
    locations = response.get("locations")
    status = response.get("statusCode", response.get("status"))
    if isinstance(status, str) and re.fullmatch(r"[0-9]{1,6}", status):
        status = int(status)
    return {"following_rows": len(rows),
            "rows_with_id": sum(isinstance(row.get("id") or row.get("fmId"), str) for row in rows),
            "rows_with_accepted_handles_list": sum(isinstance(row.get("invitationAcceptedHandles"), list) for row in rows),
            "rows_with_nonempty_accepted_handles": sum(bool(row.get("invitationAcceptedHandles")) for row in rows),
            "rows_with_opted_not_to_share_flag": sum(row.get("optedNotToShare") is True for row in rows),
            "location_rows": len(locations) if isinstance(locations, list) else 0,
            "service_status": status if type(status) is int else None}


class FriendsClient:
    def __init__(self, state, provider, trace, *, apns_token="", native_context=False):
        self.state = state
        self.provider = provider
        self.trace = trace
        self.http = AuthenticationSession(trace)
        self.login = state["login"]["data"]
        self.host = find_host(self.login["mobileme_data"])
        self.device_id = provider.account_ids["devid"]
        self.server_context = {}
        self.data_context = {}
        self.model_version = "1"
        self.apns_token = apns_token
        self.native_context = native_context
        match = re.match(r"<([^>]+)> <macOS;([^;>]+);([^>]+)>", provider.client)
        if not match:
            raise FriendsError("unsupported_machine_profile")
        self.product, self.os_version, self.build = match.groups()

    async def request(self, *, selected=None, refresh=False):
        path = "minCallback/selFriend/refreshClient" if selected is not None else "minCallback/refreshClient" if refresh else "initClient"
        headers = await self.provider.get_headers(**{
            "user_id": self.provider.account_ids["uid"], "device_id": self.device_id})
        headers = {k: v for k, v in headers.items() if k.lower() != "x-mme-client-info"}
        headers.update({"Accept": "application/json", "Accept-Language": "en-US,en;q=0.9",
                        "Content-Type": "application/json", "User-Agent": "FMFD/1.0 com.apple.iCloudHelper/282",
                        "X-Apple-AuthScheme": "Forever", "X-Apple-Find-API-Ver": "2.0",
                        "X-Apple-I-Locale": "en_US", "X-Apple-Realm-Support": "1.0",
                        "X-FMF-Model-Version": self.model_version,
                        "X-MMe-Client-Info": f"<{self.product}> <macOS;{self.os_version};{self.build}> <com.apple.AuthKit/1 (com.apple.findmy/375.20)>"})
        context = {"appName": "fmfd", "appVersion": "7.0", "apsToken": self.apns_token, "buildVersion": self.build,
                   "countryCode": "US", "currentTime": int(time.time() * 1000), "deviceClass": "Mac",
                   "deviceHasPasscode": True, "deviceUDID": self.device_id.lower(), "fencingEnabled": True,
                   "isFMFAppRemoved": False, "osVersion": self.os_version, "platform": "macosx",
                   "processId": str(os.getpid()), "productType": self.product, "regionCode": "US",
                   "selectedFriend": selected, "signedInAs": self.state["account"]["username"],
                   "timezone": "UTC, 0", "unlockState": 0}
        if self.native_context:
            context.update({"appName": "findmylocated", "callerHandleId": self.state["account"]["username"],
                            "contextBundleApp": "com.apple.findmy.findmylocated"})
        server_context = dict(self.server_context)
        # Explicit research variant from the native-client write-up. The normal
        # path remains unchanged until a live key delivery establishes usefulness.
        if self.native_context:
            mobileme_token = self.login["mobileme_data"]["tokens"].get("mmeAuthToken")
            if not isinstance(mobileme_token, str) or not mobileme_token:
                raise FriendsError("missing_mobileme_context_token")
            server_context["authToken"] = base64.b64encode(mobileme_token.encode()).decode("ascii")
            server_context.setdefault("prsId", self.login["dsid"])
        body = {"clientContext": context, "dataContext": self.data_context, "serverContext": server_context}
        auth = BasicAuth(self.login["dsid"], self.login["mobileme_data"]["tokens"]["mmeFMFAppToken"])
        session = await self.http._get_session()
        suffix = f"/fmipservice/friends/fmfd/{self.login['dsid']}/{quote(self.device_id, safe='')}/{path}"
        for attempt in range(2):
            async with session.post("https://" + self.host + suffix, json=body, headers=headers, auth=auth,
                                    ssl=self.http._ssl, allow_redirects=False) as reply:
                if self.trace is not None:
                    self.trace.http_response(reply.status, reply.headers.get("Retry-After"))
                if attempt == 0 and reply.status in {301, 302, 307, 308, 330}:
                    destination = reply.headers.get("X-Apple-MMe-Host") or reply.headers.get("Location")
                    self.host = checked_host(destination)
                    await reply.read()
                    continue
                if not 200 <= reply.status < 300:
                    raise FriendsError("friends_http_error")
                raw = await reply.read()
                if len(raw) > 4 * 1024 * 1024:
                    raise FriendsError("friends_response_too_large")
                import json
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise FriendsError("invalid_friends_response")
                version = reply.headers.get("X-FMF-Model-Version")
                if version and re.fullmatch(r"[0-9]{1,12}", version):
                    self.model_version = version
                # Delta refreshes may omit these fields; keep the last server
                # values instead of silently resetting the next request.
                for field, attribute in (("serverContext", "server_context"), ("dataContext", "data_context")):
                    if field in data:
                        if not isinstance(data[field], dict):
                            raise FriendsError("invalid_friends_context")
                        setattr(self, attribute, data[field])
                return data
        raise FriendsError("unexpected_service_redirect")

    async def close(self):
        await self.http.close()
        await self.provider.close()
