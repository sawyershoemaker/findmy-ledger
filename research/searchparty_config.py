"""Read SearchParty's feature/version/throttle configuration without location IDs."""
import argparse
import asyncio
import json
import logging
from pathlib import Path

from aiohttp import BasicAuth

from .auth_diagnostics import AuthTrace
from .fmf_client import FriendsClient
from .saved_session import restore
from . import searchparty_backoff
from .windows_secrets import load

CONFIG_FIELDS = frozenset({"featureEnabled", "acceptVersion", "keyDistributionThrottle", "configVersion", "statusCode",
    "overridePendingKeyRequestCheck", "subscriptionThrottleInSec", "maxAllowedLiveSessionCount",
    "maxAllowedSenderSessions", "locationCacheValidityThreshold", "locationAgingThreshold"})


def config_summary(value, depth=0):
    result = {}
    if depth > 5:
        return result
    if isinstance(value, dict):
        for key, item in value.items():
            if key in CONFIG_FIELDS:
                if type(item) in (bool, int, float):
                    result[key] = item
                elif isinstance(item, str) and item.isascii() and item.isdecimal() and len(item) < 9:
                    result[key] = int(item)
            if isinstance(item, (dict, list)):
                result.update(config_summary(item, depth + 1))
    elif isinstance(value, list):
        for item in value[:100]:
            result.update(config_summary(item, depth + 1))
    return result


async def probe(directory, result, *, method="GET"):
    if method not in {"GET", "POST"}:
        raise ValueError("Unsupported configuration method")
    backoff = searchparty_backoff.active(directory)
    if backoff:
        result.update(backoff)
        return
    state, provider = restore(directory)
    trace = AuthTrace()
    client = FriendsClient(state, provider, trace)
    try:
        apns = load(directory / "apns.dpapi")
        if apns.get("device_id") != client.device_id:
            raise ValueError("Push and account identities differ")
        headers = await provider.get_headers(provider.account_ids["uid"], client.device_id)
        headers = {key: value for key, value in headers.items() if key.lower() != "x-mme-client-info"}
        headers.update({"Content-Type": "application/json", "Accept": "application/json", "Accept-Version": "1",
            "User-Agent": f"searchpartyuseragent/1 {client.product}/{client.os_version}",
            "X-MMe-Client-Info": f"<{client.product}> <macOS;{client.os_version};{client.build}> <com.apple.icloud.searchpartyuseragent/1.0>"})
        body = {"clientContext": {"apsToken": apns["courier_token"].upper(), "clientId": client.device_id.lower(),
            "contextApp": "com.apple.findmy.findmylocated", "shallowStats": {}, "liveStats": {}, "nearbyWatchIdentifiers": []}}
        session = await client.http._get_session()
        # The native constructor has headers and no encoded body. GET is an
        # explicit research hypothesis; POST remains available for comparison.
        arguments = {} if method == "GET" else {"json": body}
        result["request_method"] = method
        async with session.request(method, "https://gateway.icloud.com/findmyservice/config", headers=headers, **arguments,
                auth=BasicAuth(client.login["dsid"], client.login["mobileme_data"]["tokens"]["searchPartyToken"]),
                ssl=client.http._ssl, allow_redirects=False) as reply:
            trace.http_response(reply.status, reply.headers.get("Retry-After"))
            result["http_status"] = reply.status
            if trace.retry_after_seconds is not None:
                result["retry_after_seconds"] = trace.retry_after_seconds
            backoff = searchparty_backoff.record(directory, result)
            if backoff:
                result["retry_not_before_utc"] = backoff["retry_not_before_utc"]
            raw = await searchparty_backoff.read_limited(reply.content, 1024 * 1024)
            result["response_bytes"] = len(raw)
            try:
                decoded = json.loads(raw)
                result["config"] = config_summary(decoded)
                result["response_format"] = "json"
            except (ValueError, UnicodeError):
                result["response_format"] = "other"
                body_text = raw.decode("utf-8", errors="replace").lower()
                result["service_unavailable_text"] = "service unavailable" in body_text
                result["rate_limit_text"] = "too many requests" in body_text
            result["success"] = reply.status == 200 and bool(result.get("config"))
    finally:
        await client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--method", choices=("GET", "POST"), default="GET")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    result = {"stage": "searchparty_config", "success": False, "automatic_retry": False, "location_requested": False}
    try:
        asyncio.run(probe(args.state_dir, result, method=args.method))
    except (Exception, KeyboardInterrupt) as error:
        result["error_type"] = type(error).__name__
    (args.state_dir / "searchparty-config-status.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
