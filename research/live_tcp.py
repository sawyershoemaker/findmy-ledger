"""Bounded TCP stream carried by the classic IDS relay's uncompressed UTun.

This carries encrypted IDS control frames. TCP checksum verification is not
cryptographic authentication; callers must authenticate every complete frame.
Only the session-local control port 1024 is accepted. No OS network listener.
"""
from dataclasses import dataclass
import secrets
import struct
import time

from .live_relay import RelayProtocolError

MASK = 0xffffffff
WINDOW = 65535
MSS = 1200


def distance(a, b):
    """Signed TCP sequence distance a-b, including uint32 wraparound."""
    return ((a - b + 0x80000000) & MASK) - 0x80000000


def checksum(data):
    data += b"\0" * (len(data) % 2)
    value = sum(struct.unpack("!" + str(len(data) // 2) + "H", data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return value ^ 65535


def tcp_checksum(data):
    # IDSUTunController uses tcp6checksum(NULL,NULL,...), before restoring
    # virtual IPv6 addresses at the receiver.
    return checksum(b"\0" * 32 + struct.pack("!I", len(data)) + b"\0\0\0\x06" + data)


@dataclass(frozen=True, repr=False)
class Segment:
    sequence: int
    acknowledgement: int
    flags: int
    window: int
    payload: bytes


def decode_segment(packet):
    if type(packet) is not bytes or not 21 <= len(packet) <= 65536 or packet[0] != 0x20:
        raise RelayProtocolError("Unsupported UTun control segment")
    data = packet[1:]
    source, target, seq, ack, bits, window = struct.unpack_from("!HHIIHH", data)
    header = (bits >> 12) * 4
    if source != 1024 or target != 1024 or header < 20 or header > len(data):
        raise RelayProtocolError("Invalid control TCP header")
    if tcp_checksum(data) != 0:
        raise RelayProtocolError("Control TCP checksum mismatch")
    if bits & 0x20:  # Urgent data is not part of this framing.
        raise RelayProtocolError("Unsupported urgent control data")
    return Segment(seq, ack, bits & 0x1ff, window, data[header:])


def encode_segment(sequence, acknowledgement, flags, payload=b"", *, syn=False):
    if type(payload) is not bytes or len(payload) > MSS:
        raise RelayProtocolError("Control TCP segment exceeds limit")
    options = struct.pack("!BBH", 2, 4, MSS) if syn else b""
    header = struct.pack("!HHIIHHHH", 1024, 1024, sequence & MASK, acknowledgement & MASK,
                         ((20 + len(options)) // 4 << 12) | flags, WINDOW, 0, 0)
    data = header + options + payload
    return b"\x20" + data[:16] + struct.pack("!H", tcp_checksum(data)) + data[18:]


class ControlTCP:
    def __init__(self, initial_sequence=None):
        self.initial = secrets.randbits(32) if initial_sequence is None else initial_sequence
        self.send_next = self.initial
        self.send_acked = self.initial
        self.receive_next = None
        self.peer_initial = None
        self.established = False
        self.closed = False
        self.buffer = bytearray()
        self.unacknowledged = []
        self.retry_at = None
        self.retries = 0

    def retransmit(self, now=None):
        now = time.monotonic() if now is None else now
        if not self.unacknowledged or self.closed:
            self.retry_at, self.retries = None, 0
            return []
        if self.retry_at is None:
            self.retry_at = now + 1
        if now < self.retry_at:
            return []
        if self.retries >= 6:
            raise TimeoutError("Control stream acknowledgement timed out")
        self.retries += 1
        self.retry_at = now + min(8, 2 ** self.retries)
        return [packet for _, packet in self.unacknowledged]

    def receive(self, raw):
        segment = decode_segment(raw)
        responses, frames = [], []
        if self.closed:
            return responses, frames
        if segment.flags & 2:
            if self.peer_initial is not None and segment.sequence != self.peer_initial:
                raise RelayProtocolError("Control TCP initial sequence changed")
            if segment.payload:
                raise RelayProtocolError("Unexpected control TCP fast open payload")
            self.peer_initial = segment.sequence
            if self.receive_next is None:
                self.receive_next = (segment.sequence + 1) & MASK
                self.send_next = (self.initial + 1) & MASK
            responses.append(encode_segment(self.initial, self.receive_next, 0x12, syn=True))
            return responses, frames
        if self.receive_next is None:
            raise RelayProtocolError("Control TCP handshake required")
        if segment.flags & 4:
            if segment.sequence == self.receive_next:
                self.closed = True
            return responses, frames
        if not segment.flags & 0x10:
            raise RelayProtocolError("Control TCP acknowledgement required")
        if distance(segment.acknowledgement, self.send_next) > 0:
            raise RelayProtocolError("Control TCP acknowledges unsent data")
        if distance(segment.acknowledgement, self.send_acked) >= 0:
            if segment.acknowledgement != self.send_acked:
                self.retry_at, self.retries = None, 0
            self.send_acked = segment.acknowledgement
            self.unacknowledged = [(end, packet) for end, packet in self.unacknowledged
                                   if distance(end, self.send_acked) > 0]
        if segment.acknowledgement == self.send_next:
            self.established = True
        offset = distance(segment.sequence, self.receive_next)
        if offset <= 0 and segment.payload:
            fresh = segment.payload[-offset:]
            if len(self.buffer) + len(fresh) > WINDOW:
                raise RelayProtocolError("Control TCP receive window exceeded")
            self.buffer.extend(fresh)
            self.receive_next = (self.receive_next + len(fresh)) & MASK
            while len(self.buffer) >= 2:
                size = int.from_bytes(self.buffer[:2], "big")
                if len(self.buffer) < size + 2:
                    break
                frames.append(bytes(self.buffer[2:size+2]))
                del self.buffer[:size+2]
        if segment.flags & 1 and (segment.sequence + len(segment.payload)) & MASK == self.receive_next:
            self.receive_next = (self.receive_next + 1) & MASK
            self.closed = True
        if segment.payload or segment.flags & 1:
            # Out-of-order segments are not buffered: cumulative ACK requests
            # retransmission, bounding memory even with hostile sequence gaps.
            responses.append(encode_segment(self.send_next, self.receive_next, 0x10))
        return responses, frames

    def send_frame(self, frame):
        if not self.established or self.closed or len(frame) > 65535:
            raise RelayProtocolError("Control TCP stream unavailable")
        data = struct.pack("!H", len(frame)) + frame
        if distance(self.send_next, self.send_acked) + len(data) > WINDOW:
            raise RelayProtocolError("Control TCP send window exceeded")
        packets = []
        for offset in range(0, len(data), MSS):
            part = data[offset:offset+MSS]
            packet = encode_segment(self.send_next, self.receive_next, 0x18, part)
            self.send_next = (self.send_next + len(part)) & MASK
            self.unacknowledged.append((self.send_next, packet))
            packets.append(packet)
        return packets
