"""Activate and test this client's push identity with verified TLS and no retries."""
import argparse
import asyncio
import hashlib
import json
import logging
import secrets
import time
from pathlib import Path

from .windows_secrets import load, save_atomic

TOPICS = ("com.apple.private.alloy.multiplex1", "com.apple.private.alloy.fmf",
          "com.apple.mobileme.fmf2", "com.apple.mobileme.fmf3", "com.apple.findmy")


async def connect(certificate, key, token=None):
    import anyio
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from .ids_tls import new_trust_context
    from pypush.apns import protocol, transport
    # APNs needs its own ALPN setting; never mutate the shared HTTPS context.
    context = new_trust_context()
    context.set_alpn_protocols(["apns-security-v3"])
    stream = await anyio.connect_tcp("1-courier.push.apple.com", 5223, ssl_context=context,
                                     tls_hostname="courier.push.apple.com", tls_standard_compatible=False)
    commands = protocol.CommandStream(transport.PacketStream(stream))
    try:
        nonce = b"\0" + int(time.time() * 1000).to_bytes(8, "big") + secrets.token_bytes(8)
        signature = b"\x01\x01" + key.sign(nonce, padding.PKCS1v15(), hashes.SHA1())
        await commands.send(protocol.ConnectCommand(push_token=token, state=1, flags=65,
                            certificate=certificate.public_bytes(serialization.Encoding.DER), nonce=nonce, signature=signature))
        ack = await receive_type(commands, protocol.ConnectAck)
        if ack.status != 0:
            raise ValueError("APNs connection was rejected")
        token = ack.token or token
        if not isinstance(token, bytes) or not token:
            raise ValueError("APNs returned no courier token")
        return commands, token
    except BaseException:
        await commands.aclose()
        raise


async def receive_type(commands, expected):
    async with asyncio.timeout(20):
        for _ in range(64):
            reply = await commands.receive()
            if isinstance(reply, expected):
                return reply
    raise ValueError("APNs response was missing")


async def prepare(state_dir, status):
    import httpx
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from findmy.util.tls import apple_trust_context
    from pypush.apns import albert, protocol
    identity = load(state_dir / "mac-machine.dpapi")["identity"]
    path = state_dir / "apns.dpapi"
    state = load(path) if path.exists() else {}
    if state and state.get("device_id") != identity["device_id"]:
        raise ValueError("APNs identity belongs to another machine")
    if state.get("certificate_pem"):
        cert = x509.load_pem_x509_certificate(state["certificate_pem"].encode())
        key = serialization.load_pem_private_key(state["private_key_pem"].encode(), password=None)
    else:
        status["phase"] = "apns_activation"
        async with httpx.AsyncClient(verify=apple_trust_context(), timeout=30, follow_redirects=False) as http:
            cert, key = await albert.activate(http_client=http, device_class="MacOS", udid=identity["device_id"],
                                             serial=identity["serial"], version="13.1", build="22C65", model="MacBookPro13,2")
        state = {"device_id": identity["device_id"], "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
                 "private_key_pem": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()).decode(), "scoped_tokens": {}}
        save_atomic(path, state)
    status["phase"] = "apns_connect"
    async with asyncio.timeout(40):
        commands, token = await connect(cert, key, bytes.fromhex(state["courier_token"]) if state.get("courier_token") else None)
    state["courier_token"] = token.hex()
    save_atomic(path, state)
    try:
        status["phase"] = "apns_scoped_tokens"
        for topic in TOPICS:
            if topic not in state["scoped_tokens"]:
                topic_hash = hashlib.sha1(topic.encode()).digest()
                await commands.send(protocol.ScopedTokenCommand(token=token, topic=topic_hash))
                ack = await receive_type(commands, protocol.ScopedTokenAck)
                if ack.status != 0 or ack.topic != topic_hash:
                    raise ValueError("APNs topic token was rejected")
                state["scoped_tokens"][topic] = ack.scoped_token.hex()
                save_atomic(path, state)
    finally:
        await commands.aclose()
    return {"stage": "apns_registration", "success": True, "certificate_saved_encrypted": True,
            "courier_connected": True, "tls_verified": True, "scoped_topic_count": len(state["scoped_tokens"]),
            "ids_registered": False, "live_collection_ready": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    status = {"stage": "apns_registration", "phase": "load_machine"}
    try:
        result = asyncio.run(prepare(args.state_dir, status))
        (args.state_dir / "apns-status.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        status.update({"success": False, "error_type": type(error).__name__, "automatic_retry": False,
                       "live_collection_ready": False})
        (args.state_dir / "apns-status.json").write_text(json.dumps(status, indent=2), encoding="utf-8")
        print(json.dumps(status, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
