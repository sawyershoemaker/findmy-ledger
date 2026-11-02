"""Selected-peer IDS session signaling based on public Apple build 23B85.

Pure builders and authenticated encryption only; this module opens no sockets.
Callers must freshly validate the accepted relationship and IDS directory keys.
The self-only loopback diagnostic retains its separate destination guard.
"""
from dataclasses import dataclass
import secrets
from uuid import UUID, uuid4

from .live_codec import DestinationType, encode_beacon_context

TOPIC = "com.apple.private.alloy.fmd"
RELAY_TOPIC = "com.apple.private.alloy.quickrelay"
USER_AGENT = "[macOS,13.1,22C65,MacBookPro13,2]"


@dataclass(frozen=True, repr=False)
class SelectedPeer:
    handle: str
    identity: object


def _handle(value):
    if (type(value) is not str or not value.startswith(("mailto:", "tel:"))
            or len(value) > 4096 or "\x00" in value):
        raise ValueError("Invalid account handle")
    return value


def _uuid(value):
    if not isinstance(value, UUID):
        raise ValueError("Invalid session identifier")
    return str(value).upper()


def _recipient(peer):
    if not isinstance(peer, SelectedPeer):
        raise ValueError("A verified selected peer is required")
    identity = peer.identity
    if type(identity.push_token) is not bytes or len(identity.push_token) != 32:
        raise ValueError("Invalid selected push token")
    if type(identity.session_token) is not bytes or not 1 <= len(identity.session_token) <= 4096:
        raise ValueError("Invalid selected directory token")
    return {"tP": _handle(peer.handle), "D": False, "sT": identity.session_token, "t": identity.push_token}


def invitation(session_id, participant_id, peer):
    _recipient(peer)
    # findmylocated saves MessageContext.fromID (device-scoped) as ownerHandle,
    # then passes that Destination to the native session and its context.
    destination = "token:" + peer.identity.push_token.hex() + "/" + peer.handle
    return {"v": 5, "s": _uuid(session_id), "p": _uuid(participant_id), "t": 0,
            "d": True, "c": encode_beacon_context(DestinationType.APS_TOKEN, destination),
            "pcd": False, "de": False, "sd": False, "mi": True, "sqr": True,
            "rt": False, "cc": True, "pclm": True, "re": True}


def cancellation(session_id, participant_id):
    return {"v": 5, "s": _uuid(session_id), "p": _uuid(participant_id)}


def allocation_request(session_id, sender, peer, *, request_id=None):
    _uuid(session_id)
    request_id = uuid4() if request_id is None else request_id
    _uuid(request_id)
    # Native one-to-one allocation is type 1. The group transport uses type 3.
    # _IDSAllocateProtocolVersionNumber in 23B85 returns NSNumber(25).
    return {"c": 200, "i": secrets.randbits(31), "U": request_id.bytes,
            "sP": _handle(sender), "ua": USER_AGENT, "dtl": [_recipient(peer)],
            "qids": session_id.bytes, "qat": 1, "qv": 25, "qai": TOPIC, "qsats": 0}


def seal_message(ids, sender_identity, recipient_identity, plaintext, *, counter):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    if type(plaintext) is not bytes or not 1 <= len(plaintext) <= 1024 * 1024:
        raise ValueError("Invalid signaling payload")
    if type(counter) is not int or not 0 <= counter < 0xffffffff:
        raise ValueError("Invalid replay counter")
    sender = serialization.load_pem_private_key(sender_identity["device_private_key_pem"].encode(), None)
    ephemeral = ids._generate_compact_p256()
    sender_x = ids._compact_public_key(sender)
    recipient_x = recipient_identity.device_public_key.public_numbers().x.to_bytes(32, "big")
    prekey_x = recipient_identity.prekey_public_key.public_numbers().x.to_bytes(32, "big")
    ephemeral_x = ids._compact_public_key(ephemeral)
    secret = ephemeral.exchange(ec.ECDH(), recipient_identity.prekey_public_key)
    material = HKDF(algorithm=hashes.SHA256(), length=48, salt=b"LastPawn-MessageKeys", info=b"").derive(secret)
    inner = ids._proto_bytes(1, plaintext) + b"\x10" + ids._varint(counter)
    padding = (-len(inner)) % 16
    padded = inner + b"\0" * padding + padding.to_bytes(4, "little")
    cipher = Cipher(algorithms.AES(material[:32]), modes.CTR(material[32:])).encryptor()
    encrypted = cipher.update(padded) + cipher.finalize()
    # The signature binds both recipient keys, plus the fresh ephemeral key.
    signed = secret + prekey_x + ephemeral_x + recipient_x + encrypted
    r, s = utils.decode_dss_signature(sender.sign(signed, ec.ECDSA(hashes.SHA256())))
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    validator = sender_x[:2] + recipient_x[:2] + prekey_x[:2] + b"\x0d"
    return (ids._proto_bytes(1, encrypted) + ids._proto_bytes(2, ephemeral_x)
            + ids._proto_bytes(3, signature) + ids._proto_bytes(99, validator))


def session_envelope(command, sender, peer, encrypted, *, message_id=None):
    if type(command) is not int or command not in (232, 235, 236):
        raise ValueError("Unsupported outbound session command")
    if type(encrypted) is not bytes or not encrypted or len(encrypted) > 1024 * 1024:
        raise ValueError("Invalid encrypted session message")
    message_id = uuid4() if message_id is None else message_id
    _uuid(message_id)
    recipient = {**_recipient(peer), "P": encrypted, "E": "pair-ec"}
    return {"fcn": 1, "c": command, "E": "pair", "ua": USER_AGENT, "v": 8,
            "i": secrets.randbits(31), "U": message_id.bytes, "sP": _handle(sender),
            "nr": True, "dtl": [recipient]}
