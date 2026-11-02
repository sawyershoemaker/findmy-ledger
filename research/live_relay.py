"""Authenticated classic QuickRelay STUN binding for one-to-one IDS sessions.

Constants come from IDSFoundation in public Apple build 23B85. This is not the
shared-group QUIC protocol. Successful relay binding alone is not a Live stream.
"""
import asyncio
from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import secrets
import socket
import struct
from uuid import uuid4

COOKIE = 0x2112A442
ALLOCATE_BIND = 0x0EE0
ALLOCATE_SUCCESS = 0x0FE0
INTEGRITY = 0x0008
SESSION_TOKEN = 0xFFF2
REQUESTED_TRANSPORT = 0x0019
CHANNEL_NUMBER = 0x000C
ERROR_CODE = 0x0009


class RelayProtocolError(ValueError):
    pass


@dataclass(frozen=True, repr=False)
class StunMessage:
    type: int
    transaction: bytes
    attributes: dict


def encode_stun(kind, transaction, attributes, key):
    if type(kind) is not int or not 0 <= kind < 0x4000:
        raise RelayProtocolError("Invalid STUN type")
    if type(transaction) is not bytes or len(transaction) != 12:
        raise RelayProtocolError("Invalid STUN transaction")
    if type(key) is not bytes or not 1 <= len(key) <= 256:
        raise RelayProtocolError("Invalid STUN authentication key")
    encoded, seen = [], set()
    for attribute, data in attributes:
        if type(attribute) is not int or not 0 <= attribute <= 65535 or attribute in seen or attribute == INTEGRITY:
            raise RelayProtocolError("Invalid STUN attribute")
        if type(data) is not bytes or len(data) > 4096:
            raise RelayProtocolError("Invalid STUN attribute size")
        seen.add(attribute)
        encoded.append(struct.pack("!HH", attribute, len(data)) + data + b"\0" * (-len(data) % 4))
    body = b"".join(encoded)
    if len(body) > 16 * 1024:
        raise RelayProtocolError("STUN message exceeds limit")
    authenticated = struct.pack("!HHI12s", kind, len(body) + 24, COOKIE, transaction) + body
    return authenticated + struct.pack("!HH", INTEGRITY, 20) + hmac.digest(key, authenticated, hashlib.sha1)


def decode_stun(data, key, *, transaction=None):
    if type(data) is not bytes or not 44 <= len(data) <= 16 * 1024 + 44:
        raise RelayProtocolError("Invalid STUN packet size")
    kind, size, cookie, identifier = struct.unpack_from("!HHI12s", data)
    if kind >= 0x4000 or cookie != COOKIE or size % 4 or size != len(data) - 20:
        raise RelayProtocolError("Invalid STUN header")
    if transaction is not None and identifier != transaction:
        raise RelayProtocolError("STUN transaction mismatch")
    attrs, pos = {}, 20
    while pos < len(data):
        if len(data) - pos < 4:
            raise RelayProtocolError("Truncated STUN attribute header")
        attribute, length = struct.unpack_from("!HH", data, pos)
        end = pos + 4 + ((length + 3) & ~3)
        if end > len(data) or attribute in attrs:
            raise RelayProtocolError("Invalid or duplicate STUN attribute")
        attrs[attribute] = data[pos + 4:pos + 4 + length]
        if attribute == INTEGRITY:
            if length != 20 or end != len(data):
                raise RelayProtocolError("STUN integrity must be last")
            expected = hmac.digest(key, data[:pos], hashlib.sha1)
            if not hmac.compare_digest(expected, attrs[attribute]):
                raise RelayProtocolError("STUN authentication failed")
        pos = end
    if INTEGRITY not in attrs:
        raise RelayProtocolError("Missing STUN authentication")
    return StunMessage(kind, identifier, attrs)


class RelayBinding:
    def __init__(self, allocation):
        address, port = allocation.get("qrip"), allocation.get("qrp")
        key, token = allocation.get("qrsk"), allocation.get("qrst")
        if type(address) is not bytes or len(address) != 4 or type(port) is not int or not 1 <= port <= 65535:
            raise RelayProtocolError("Unsupported relay endpoint")
        address = ipaddress.IPv4Address(address)
        if not address.is_global:
            raise RelayProtocolError("Relay endpoint is not public")
        if type(key) is not bytes or len(key) != 20 or type(token) is not bytes or not 1 <= len(token) <= 4096:
            raise RelayProtocolError("Invalid relay credentials")
        self.key, self.token = key, token
        self.endpoint = (str(address), port)
        self.socket = None
        self.channel = None
        self.control_key = allocation.get("qids")
        self.link_uuid = uuid4().bytes
        self.mapped_address = None
        self.received_connected = False
        self.received_connected_ack = False
        self.connected_resends = 0

    async def bind(self, status):
        loop = asyncio.get_running_loop()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setblocking(False)
        await loop.sock_connect(self.socket, self.endpoint)
        transaction = secrets.token_bytes(12)
        packet = encode_stun(ALLOCATE_BIND, transaction,
            [(SESSION_TOKEN, self.token), (REQUESTED_TRANSPORT, b"\x11\0\0\0")], self.key)
        for attempt in range(2):
            await loop.sock_sendall(self.socket, packet)
            status["allocbind_attempts"] = attempt + 1
            try:
                raw = await asyncio.wait_for(loop.sock_recv(self.socket, 65536), 3)
            except TimeoutError:
                continue
            response = decode_stun(raw, self.key, transaction=transaction)
            status.update(response_authenticated=True, response_type=response.type,
                          attribute_types=sorted(response.attributes))
            if ERROR_CODE in response.attributes:
                error = response.attributes[ERROR_CODE]
                if len(error) >= 4:
                    status["server_error_code"] = (error[2] & 7) * 100 + error[3]
                raise RelayProtocolError("Relay rejected binding")
            channel = response.attributes.get(CHANNEL_NUMBER)
            if response.type != ALLOCATE_SUCCESS or type(channel) is not bytes or len(channel) != 4:
                raise RelayProtocolError("Unexpected relay binding response")
            self.channel = struct.unpack_from("!H", channel)[0]
            if not 0x4000 <= self.channel <= 0x7fff:
                raise RelayProtocolError("Invalid relay channel")
            mapped = response.attributes.get(32)
            if isinstance(mapped, bytes) and len(mapped) == 8 and mapped[:2] == b"\0\x01":
                self.mapped_address = mapped[:2] + bytes(
                    a ^ b for a, b in zip(mapped[2:], struct.pack("!HI", COOKIE >> 16, COOKIE)))
            status["relay_bound"] = True
            return raw
        raise TimeoutError("Relay binding timed out")

    def close(self):
        if self.socket is not None:
            self.socket.close()
            self.socket = None

    async def receive(self):
        if self.socket is None or self.channel is None:
            raise RelayProtocolError("Relay is not bound")
        return await asyncio.get_running_loop().sock_recv(self.socket, 65536)

    async def send_control(self, command, attributes):
        from .live_control import encode_control, encode_indication
        if self.socket is None or self.channel is None:
            raise RelayProtocolError("Relay is not bound")
        data = encode_control(command, attributes, self.control_key)
        await asyncio.get_running_loop().sock_sendall(self.socket, encode_indication(self.channel, data))

    async def start_control(self):
        from .live_control import connected_attributes
        await self.send_control(1, connected_attributes(self.link_uuid, self.mapped_address))

    async def send_data(self, data):
        if self.socket is None or self.channel is None or not 1 <= len(data) <= 1400:
            raise RelayProtocolError("Invalid relay data send")
        await asyncio.get_running_loop().sock_sendall(self.socket,
            struct.pack("!HH", self.channel, len(data)) + data)

    def channel_payload(self, packet):
        if len(packet) < 4:
            raise RelayProtocolError("Truncated relay data")
        channel, size = struct.unpack_from("!HH", packet)
        if channel != self.channel or size != len(packet) - 4:
            raise RelayProtocolError("Invalid relay data channel or size")
        return packet[4:]

    async def handle_control(self, packet):
        from .live_control import connected_attributes, decode_indication
        message = decode_indication(packet, self.channel, self.control_key)
        command, attrs = message.command, message.attributes
        if command == 1:
            self.received_connected = True
            await self.send_control(32769, connected_attributes(self.link_uuid, self.mapped_address, response=True))
            if not self.received_connected_ack and self.connected_resends < 3:
                await self.start_control()
                self.connected_resends += 1
        elif command == 32769:
            self.received_connected_ack = True
        elif command in (2, 3, 4, 5, 6):
            reply = [(1, attrs[1])] if 1 in attrs else []
            if command == 6:
                reply.append((12, b"\0\x01"))
            await self.send_control(command | 0x8000, reply)
        return {"kind": "global_link_control", "bytes": len(packet),
            "session_control_authenticated": True, "authenticated": False,
            "command": command, "attribute_sizes": {str(k): len(v) for k, v in attrs.items()},
            "connected_exchange_complete": self.received_connected and self.received_connected_ack}

    def packet_summary(self, packet):
        """Shape only. Channel data still needs end-to-end authentication."""
        summary = {"bytes": len(packet), "authenticated": False}
        if len(packet) < 2:
            summary["kind"] = "short"
            return summary
        kind = struct.unpack_from("!H", packet)[0]
        if kind < 0x4000:
            message = decode_stun(packet, self.key)
            summary.update(kind="stun", authenticated=True, message_type=message.type,
                attribute_sizes={str(k): len(v) for k, v in message.attributes.items()})
        elif kind <= 0x7fff:
            summary.update(kind="channel", channel_matches=kind == self.channel)
            if len(packet) >= 4:
                summary["declared_payload_bytes"] = struct.unpack_from("!H", packet, 2)[0]
        else:
            summary["kind"] = "other"
        return summary
