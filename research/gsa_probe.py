"""Two credential-free requests comparing old and current GSA client identifiers."""
import asyncio
import json
import logging
import ssl


async def probe():
    from findmy import LocalAnisetteProvider
    from findmy.util.http import HttpSession
    from .auth_probe import check_version
    check_version()
    provider = LocalAnisetteProvider()
    session = HttpSession()
    try:
        if not isinstance(session._ssl, ssl.SSLContext) or not session._ssl.check_hostname or session._ssl.verify_mode != ssl.CERT_REQUIRED:
            raise RuntimeError("This probe requires verified TLS")
        clients = {
            "old_xcode_identifier": "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>",
            "current_akd_identifier": provider.client,
        }
        results = []
        for label, client in clients.items():
            response = await session.post("https://gsa.apple.com/grandslam/GsService2",
                                          headers={"X-MMe-Client-Info": client}, data=b"t")
            results.append({"client": label, "http_status": response.status_code})
        return {"credential_free": True, "tls_certificate_verified": True,
                "account_sign_in_attempted": False, "requests": results,
                "interpretation": "A 401 response to this deliberately unauthenticated request is expected; it does not prove account login."}
    finally:
        await session.close()
        await provider.close()


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    try:
        print(json.dumps(asyncio.run(probe()), indent=2))
    except Exception as error:
        print(json.dumps({"success": False, "error_type": type(error).__name__}))
        raise SystemExit(2)
