"""Bounded encrypted IDS loopback to this Windows identity only.

No recipient argument, participant lookup, phone delivery, or location operation.
The sole destination token must equal this connection's registered base token.
"""
import argparse
import asyncio
import hmac
import json
import logging
import plistlib
import secrets
import sys
from contextlib import AsyncExitStack
from pathlib import Path

from .auth_diagnostics import AuthTrace, status_number
from .ids_probe import install_verified_transport
from .push_receiver import verified_connection
from .windows_secrets import load


def seal_probe(ids, identity, directory, plaintext):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    device = serialization.load_pem_private_key(identity["device_private_key_pem"].encode(), None)
    prekey = serialization.load_pem_private_key(identity["pre_private_key_pem"].encode(), None)
    if (device.public_key().public_numbers() != directory.device_public_key.public_numbers()
            or prekey.public_key().public_numbers() != directory.prekey_public_key.public_numbers()):
        raise ValueError("Directory identity differs from this receiver's keys")
    ephemeral = ids._generate_compact_p256()
    device_x = ids._compact_public_key(device)
    prekey_x = ids._compact_public_key(prekey)
    ephemeral_x = ids._compact_public_key(ephemeral)
    secret = ephemeral.exchange(ec.ECDH(), directory.prekey_public_key)
    material = HKDF(algorithm=hashes.SHA256(), length=48, salt=b"LastPawn-MessageKeys", info=b"").derive(secret)
    inner = ids._proto_bytes(1, plaintext)
    padding = (-len(inner)) % 16
    padded = inner + b"\0" * padding + padding.to_bytes(4, "little")
    encryptor = Cipher(algorithms.AES(material[:32]), modes.CTR(material[32:])).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    signed = secret + prekey_x + ephemeral_x + device_x + encrypted
    r, s = utils.decode_dss_signature(device.sign(signed, ec.ECDSA(hashes.SHA256())))
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    validator = device_x[:2] + device_x[:2] + prekey_x[:2] + b"\x0c"
    return (ids._proto_bytes(1, encrypted) + ids._proto_bytes(2, ephemeral_x)
            + ids._proto_bytes(3, signature) + ids._proto_bytes(99, validator))


def self_envelope(*, handle, base_token, directory, payload, challenge_id):
    if not hmac.compare_digest(base_token, directory.push_token):
        raise ValueError("Loopback refuses any destination other than this receiver")
    if not isinstance(challenge_id, bytes) or len(challenge_id) != 16:
        raise ValueError("Invalid loopback challenge identifier")
    return {"fcn": 1, "c": 242, "E": "pair", "ua": "[macOS,13.1,22C65,MacBookPro13,2]", "v": 8,
            "i": int.from_bytes(secrets.token_bytes(4), "big") & 0x7fffffff, "U": challenge_id,
            "sP": handle, "nr": True,
            "dtl": [{"tP": handle, "D": False, "sT": directory.session_token,
                     "t": base_token, "P": payload, "E": "pair-ec"}]}


async def probe(state_dir, stats):
    config = json.loads((state_dir / "push-helper-config.json").read_text())
    if config["onitrack_commit"] != "04dd25312643d8c9aa93c883a343488a4b682635":
        raise ValueError("Unexpected protocol implementation")
    sys.path.insert(0, config["onitrack_path"])
    from onitrack import ids, key_acquisition as protocol
    from pypush.apns.protocol import SendMessageCommand
    install_verified_transport(ids, AuthTrace())
    registered, apns = load(state_dir / "ids.dpapi"), load(state_dir / "apns.dpapi")
    machine = load(state_dir / "mac-machine.dpapi")["identity"]
    if not registered.get("registered") or any(item.get("device_id") != machine["device_id"] for item in (registered, apns)):
        raise ValueError("Saved registered identities do not match")
    certificate, key, token = protocol._load_apns_material(apns)
    handle = protocol._registered_self_handle(registered)
    client = protocol.IDSDirectoryClient(registered, user_agent="[macOS,13.1,22C65,MacBookPro13,2]")
    topic = "com.apple.private.alloy.fmd"
    await asyncio.to_thread(ids._bag, "id-query")
    async with asyncio.timeout(65):
        async with verified_connection(certificate, key, token, stats=stats.setdefault("transport", {})) as connection:
            await protocol._set_apns_active(connection)
            async with AsyncExitStack() as stack:
                await stack.enter_async_context(connection.notification_stream(protocol.IDS_PARENT_TOPIC))
                stream = await stack.enter_async_context(connection.notification_stream(topic))
                directory = await client.query_sender(connection, base_token=token, topic=topic,
                                                     sender=handle, target=handle, sender_token=token)
                plaintext = plistlib.dumps({"probe": "findmy-ledger-loopback", "challenge": secrets.token_bytes(32)},
                                          fmt=plistlib.FMT_BINARY)
                payload = seal_probe(ids, registered["identity"], directory, plaintext)
                stats["directory_matches_local_keys"] = True
                # Verify the ciphertext locally before making a real send.
                if not hmac.compare_digest(protocol.decrypt_pair_ec(payload, receiver_identity=registered["identity"],
                    sender_identity=directory), plaintext):
                    raise ValueError("Local encrypted loopback failed")
                stats["local_crypto_verified"] = True
                challenge_id = secrets.token_bytes(16)
                envelope = self_envelope(handle=handle, base_token=token, directory=directory,
                                         payload=payload, challenge_id=challenge_id)
                await connection._send(SendMessageCommand(topic=topic, token=token,
                    payload=plistlib.dumps(envelope, fmt=plistlib.FMT_BINARY),
                    id=envelope["i"].to_bytes(4, "big"), outgoing=True))
                stats["self_message_sent"] = True
                deadline = asyncio.get_running_loop().time() + 20
                while True:
                    remaining = deadline - asyncio.get_running_loop().time()
                    if remaining <= 0:
                        raise TimeoutError()
                    message = await asyncio.wait_for(stream.receive(), remaining)
                    response = plistlib.loads(message.payload)
                    if not isinstance(response, dict):
                        continue
                    code = status_number(response.get("c"))
                    if code is not None:
                        counts = stats.setdefault("commands", {})
                        counts[str(code)] = counts.get(str(code), 0) + 1
                    if response.get("U") != challenge_id:
                        continue
                    if code != 242:
                        status = status_number(response.get("s", response.get("status")))
                        if status is not None:
                            stats["delivery_status"] = status
                        continue
                    if (response.get("sP") != handle or response.get("tP") != handle
                            or response.get("t") != token or response.get("E") != "pair-ec"):
                        raise ValueError("Loopback identity binding failed")
                    decoded = protocol.decrypt_pair_ec(response["P"], receiver_identity=registered["identity"],
                                                       sender_identity=directory)
                    if not hmac.compare_digest(decoded, plaintext):
                        raise ValueError("Loopback payload differs")
                    await connection.ack(message)
                    stats["peer_delivery_verified"] = True
                    return


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    result = {"stage": "ids_self_loopback", "success": False, "participant_contacted": False,
              "phone_targeted": False, "automatic_retry": False, "live_collection_ready": False}
    try:
        asyncio.run(probe(args.state_dir.resolve(), result))
        result["success"] = True
    except (Exception, KeyboardInterrupt) as error:
        result["error_type"] = type(error).__name__
    (args.state_dir / "ids-self-status.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
