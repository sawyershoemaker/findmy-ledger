"""Classic IDS GlobalLink control, derived from public Apple build 23B85.

GlobalLink uses unpadded TLVs inside unsigned STUN indications. Its HMAC key is
the session UUID. This authenticates session control, not application data or
the sender's device identity; those require separate end-to-end verification.
"""
from dataclasses import dataclass
import hashlib
import hmac
import struct

from .live_relay import COOKIE, RelayProtocolError

HMAC = 9
U16 = frozenset((1, 2, 5, 6, 12, 18, 19))
U32 = frozenset((7, 17, 20))


@dataclass(frozen=True, repr=False)
class ControlMessage:
    command: int
    attributes: dict


def _attribute_size(kind, data):
    if (kind in U16 and len(data) != 2 or kind in U32 and len(data) != 4
            or kind == 8 and len(data) not in (8, 20)
            or kind == 11 and len(data) != 16):
        raise RelayProtocolError("Invalid GlobalLink attribute size")


def encode_control(command, attributes, session_key):
    if type(command) is not int or not 0 <= command <= 65535:
        raise RelayProtocolError("Invalid GlobalLink command")
    if type(session_key) is not bytes or len(session_key) != 16:
        raise RelayProtocolError("Invalid GlobalLink session key")
    parts, seen = [], set()
    for kind, data in attributes:
        if type(kind) is not int or not 0 < kind <= 65535 or kind == HMAC or kind in seen:
            raise RelayProtocolError("Invalid GlobalLink attribute")
        if type(data) is not bytes or len(data) > 960:
            raise RelayProtocolError("Invalid GlobalLink attribute data")
        _attribute_size(kind, data)
        seen.add(kind)
        parts.append(struct.pack("!HH", kind, len(data)) + data)
    body = b"".join(parts)
    if len(body) > 980:
        raise RelayProtocolError("GlobalLink message exceeds limit")
    prefix = struct.pack("!HH16s", command, len(body) + 24, b"\0" * 16) + body
    return prefix + struct.pack("!HH", HMAC, 20) + hmac.digest(session_key, prefix, hashlib.sha1)


def decode_control(packet, session_key):
    if type(packet) is not bytes or not 44 <= len(packet) <= 1024:
        raise RelayProtocolError("Invalid GlobalLink message size")
    if type(session_key) is not bytes or len(session_key) != 16:
        raise RelayProtocolError("Invalid GlobalLink session key")
    command, length, zero = struct.unpack_from("!HH16s", packet)
    if length != len(packet) - 20 or any(zero):
        raise RelayProtocolError("Invalid GlobalLink header")
    if packet[-24:-20] != struct.pack("!HH", HMAC, 20):
        raise RelayProtocolError("Missing GlobalLink authentication")
    if not hmac.compare_digest(hmac.digest(session_key, packet[:-24], hashlib.sha1), packet[-20:]):
        raise RelayProtocolError("GlobalLink authentication failed")
    attrs, pos = {}, 20
    while pos < len(packet):
        if pos + 4 > len(packet):
            raise RelayProtocolError("Truncated GlobalLink attribute")
        kind, size = struct.unpack_from("!HH", packet, pos)
        end = pos + 4 + size
        if end > len(packet) or kind in attrs or kind == HMAC and end != len(packet):
            raise RelayProtocolError("Invalid GlobalLink attribute")
        value = packet[pos + 4:end]
        _attribute_size(kind, value)
        attrs[kind] = value
        pos = end
    return ControlMessage(command, attrs)


def encode_indication(channel, payload):
    if type(channel) is not int or not 0x4000 <= channel <= 0x7fff:
        raise RelayProtocolError("Invalid relay channel")
    if type(payload) is not bytes or not 44 <= len(payload) <= 1024:
        raise RelayProtocolError("Invalid control indication size")
    attrs = struct.pack("!HHHHHH", 12, 4, channel, 0, 19, len(payload))
    body = attrs + payload + b"\0" * (-len(payload) % 4)
    return struct.pack("!HHI12s", 22, len(body), COOKIE, b"\0" * 12) + body


def decode_indication(packet, channel, session_key):
    if type(packet) is not bytes or not 64 <= len(packet) <= 1200:
        raise RelayProtocolError("Invalid control indication size")
    kind, length, cookie = struct.unpack_from("!HHI", packet)
    if kind != 23 or cookie != COOKIE or length != len(packet) - 20 or length % 4:
        raise RelayProtocolError("Invalid control indication header")
    attrs, pos = {}, 20
    while pos < len(packet):
        if pos + 4 > len(packet):
            raise RelayProtocolError("Truncated indication attribute")
        kind, size = struct.unpack_from("!HH", packet, pos)
        end = pos + 4 + ((size + 3) & ~3)
        if end > len(packet) or kind in attrs:
            raise RelayProtocolError("Invalid indication attribute")
        attrs[kind] = packet[pos + 4:pos + 4 + size]
        pos = end
    if attrs.get(12) != struct.pack("!HH", channel, 0) or 19 not in attrs:
        raise RelayProtocolError("Indication channel mismatch")
    return decode_control(attrs[19], session_key)


def connected_attributes(link_uuid, mapped_address=None, *, response=False):
    attrs = [(2, struct.pack("!H", 2)), (5, b"\0\0"), (6, struct.pack("!H", 1300)),
             (12, b"\0\x01"), (19, b"\0\0"), (20, b"\0\0\0\0")]
    if mapped_address is not None:
        _attribute_size(8, mapped_address)
        attrs.append((8, mapped_address))
    if not response:
        attrs.extend(((11, link_uuid), (18, b"\0\x02")))
    return attrs
