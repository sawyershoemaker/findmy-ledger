"""Read only Find My service routing from the signed-in account settings."""
import argparse
import asyncio
import json
import logging
import plistlib
import re
from pathlib import Path
from urllib.parse import urlsplit

from aiohttp import BasicAuth

from .auth_cooldown import active, record
from .auth_diagnostics import AuthTrace
from .fmf_client import FriendsClient
from .saved_session import restore
from .searchparty_backoff import read_limited
from .windows_secrets import save_atomic

# people_url is visible in the native constructor. The secure-location field
# name is an unconfirmed candidate: its absence does not prove a missing route.
ROUTE_FIELDS = frozenset({"people_url", "secureLocationsServiceURL"})
SERVICE_NAMES = frozenset({"Findme", "FindMy", "FindMyFriends", "SearchParty", "DeviceLocator", "FMF", "FindMyDevice", "FindMyiPhone"})


def route_candidates(value, *, depth=0):
    """Discover only gateway/People service URLs, independent of bag key names."""
    if depth > 12:
        raise ValueError("Account settings nesting exceeds the probe limit")
    if isinstance(value, dict):
        return set().union(*(route_candidates(child, depth=depth + 1) for name, child in value.items()
                             if name != "tokens"))
    if isinstance(value, list):
        return set().union(*(route_candidates(child, depth=depth + 1) for child in value))
    if isinstance(value, str) and value.startswith("https://"):
        parsed = urlsplit(value)
        if (not parsed.username and not parsed.password and not parsed.query and not parsed.fragment
                and parsed.port in (None, 443)
                and (re.fullmatch(r"(?:p[0-9]{1,3}-)?fmfmobile\.icloud\.com", parsed.hostname or "")
                     or parsed.hostname == "gateway.icloud.com" and parsed.path.startswith("/findmyservice"))):
            return {value}
    return set()


def service_map_routes(value):
    """Account-settings uses a webservices map before native dataclass mapping."""
    services = value.get("webservices") if isinstance(value, dict) else None
    summary = {"webservices_present": isinstance(services, dict)}
    routes = {}
    if not isinstance(services, dict):
        return routes, summary
    summary["service_entry_count"] = len(services)
    summary["recognized_services"] = sorted(SERVICE_NAMES.intersection(services))
    for service in summary["recognized_services"]:
        entry = services[service]
        if not isinstance(entry, dict):
            continue
        kept = {}
        for field in ("url", "appHostname", "people_url", "secureLocationsServiceURL"):
            candidate = entry.get(field)
            if not isinstance(candidate, str):
                continue
            parsed = urlsplit(candidate if "://" in candidate else "https://" + candidate)
            if (parsed.scheme == "https" and not parsed.username and not parsed.password and not parsed.query
                    and not parsed.fragment and parsed.port in (None, 443)
                    and re.fullmatch(r"(?:gateway|(?:p[0-9]{1,3}-)?(?:fmfmobile|fmipmobile|fmip))\.icloud\.com", parsed.hostname or "")):
                kept[field] = candidate
        if kept:
            routes[service] = kept
    summary["findmy_service_route_count"] = sum(len(entry) for entry in routes.values())
    return routes, summary


def extract_routes(value, *, depth=0):
    routes = {}
    if depth > 12:
        raise ValueError("Account settings nesting exceeds the probe limit")
    if isinstance(value, dict):
        for field, child in value.items():
            if field in ROUTE_FIELDS:
                if not isinstance(child, str):
                    raise ValueError("Invalid Find My service route")
                target = urlsplit(child)
                if (target.scheme != "https" or target.username or target.password or target.query or target.fragment
                        or target.port not in (None, 443)
                        or not re.fullmatch(r"(?:gateway|(?:p[0-9]{1,3}-)?fmfmobile)\.icloud\.com", target.hostname or "")):
                    raise ValueError("Unsupported Find My service route")
                if field in routes and routes[field] != child:
                    raise ValueError("Ambiguous Find My service routes")
                routes[field] = child
            elif isinstance(child, (dict, list)) and field != "tokens":
                for name, route in extract_routes(child, depth=depth + 1).items():
                    if name in routes and routes[name] != route:
                        raise ValueError("Ambiguous Find My service routes")
                    routes[name] = route
    elif isinstance(value, list):
        for child in value:
            for name, route in extract_routes(child, depth=depth + 1).items():
                if name in routes and routes[name] != route:
                    raise ValueError("Ambiguous Find My service routes")
                routes[name] = route
    return routes


async def probe(directory, trace, result):
    pause = active(directory)
    if pause:
        result.update(pause)
        return
    state, provider = restore(directory)
    client = FriendsClient(state, provider, trace)
    try:
        trace.enter("people_key_setup")
        headers = await provider.get_headers(provider.account_ids["uid"], client.device_id)
        headers = {name: value for name, value in headers.items() if name.lower() != "x-mme-client-info"}
        headers.update({"X-MMe-Client-Info": provider.mobileme_client,
            "User-Agent": "com.apple.iCloudHelper/282 CFNetwork/1404.0.5 Darwin/22.2.0",
            "Accept": "application/x-apple-plist"})
        session = await client.http._get_session()
        async with session.post("https://setup.icloud.com/setup/get_account_settings", headers=headers,
                auth=BasicAuth(client.login["dsid"], client.login["mobileme_data"]["tokens"]["mmeAuthToken"]),
                ssl=client.http._ssl, allow_redirects=False) as reply:
            result["http_status"] = reply.status
            if reply.status != 200:
                result["reason"] = "account_settings_rejected"
                if trace.retry_after_seconds is not None:
                    result["retry_after_seconds"] = trace.retry_after_seconds
                return
            raw = await read_limited(reply.content, 2 * 1024 * 1024)
            settings = plistlib.loads(raw)
            routes = extract_routes(settings)
            services, schema = service_map_routes(settings)
            candidates = sorted(route_candidates(settings))
            result.update(schema)
            result.update(response_bytes=len(raw), routing_fields=sorted(routes), success=True,
                expected_secure_route_field_found="secureLocationsServiceURL" in routes,
                secure_route_matches_default=routes.get("secureLocationsServiceURL", "").rstrip("/") == "https://gateway.icloud.com/findmyservice",
                candidate_url_count=len(candidates),
                default_gateway_candidate_present=any(candidate.rstrip("/") == "https://gateway.icloud.com/findmyservice" for candidate in candidates))
            save_atomic(directory / "service-routes.dpapi", {"account_dsid": client.login["dsid"],
                        "device_id": client.device_id, "routes": routes, "services": services, "candidates": candidates})
    finally:
        await client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True, type=Path)
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    trace = AuthTrace()
    result = {"stage": "findmy_service_routes", "success": False, "location_requested": False,
              "automatic_retry": False, "live_collection_ready": False}
    try:
        asyncio.run(probe(args.state_dir, trace, result))
    except (Exception, KeyboardInterrupt) as error:
        result.update(trace.failure(error))
        result["stage"] = "findmy_service_routes"
    record(args.state_dir, result)
    (args.state_dir / "service-routes-status.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result.get("success") else 2


if __name__ == "__main__":
    raise SystemExit(main())
