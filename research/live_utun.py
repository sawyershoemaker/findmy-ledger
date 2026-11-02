"""Selected-session UTun channel setup and classic IDS stream encryption.

The transport cipher has no authentication tag. Its output must not be treated
as authenticated location data: authenticate the inner Find My report first.
"""
from dataclasses import dataclass
import secrets
import struct
from uuid import UUID, uuid4, uuid5, NAMESPACE_URL

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .live_pair import decrypt_pair, encrypt_pair
from .live_relay import RelayProtocolError
from .live_tcp import checksum


def _aes_cbc(key, data):
    enc = Cipher(algorithms.AES(key), modes.CBC(b"\0"*16)).encryptor()
    return enc.update(data) + enc.finalize()


def stream_keys(material):
    if type(material) is not bytes or len(material) != 30:
        raise RelayProtocolError("Invalid IDS stream key material")
    master, salt = material[:16], material[16:]
    # IDSStreamEncryption uses CBC here, including chaining the two blocks
    # for its 256-bit derived key. Packet counters themselves use AES-ECB.
    key = _aes_cbc(master, salt+b"\0\0"+salt+b"\0\x01")
    counter = bytearray(salt+b"\0\0")
    counter[7] ^= 2
    return key, _aes_cbc(master, bytes(counter))[:14]


def stream_transform(material, ssrc, index, payload):
    if type(payload) is not bytes or len(payload) > 1600 or not 0 <= index < 1 << 48:
        raise RelayProtocolError("Invalid IDS stream packet")
    key, salt = stream_keys(material)
    nonce = bytearray(salt+b"\0\0")
    # Native counter: salt XOR [0*4,SSRC*4,ROC*4,SEQ*2,0*2].
    source = b"\0"*4 + struct.pack("!IIH", ssrc, index >> 16, index & 65535) + b"\0\0"
    nonce = bytes(a ^ b for a, b in zip(nonce, source))
    transform = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return transform.update(payload) + transform.finalize()


def _text(value):
    data = value.encode("utf-8")
    return struct.pack("!H", len(data)) + data


def hello(device_id, instance_id):
    try:
        device_uuid = UUID(device_id)
    except ValueError:
        # The enrolled Mac machine identifier may be a 40-hex UDID. This
        # optional transport GUID is separate from the authenticated IDS ID.
        device_uuid = uuid5(NAMESPACE_URL, "FindMyLedger:UTun:"+device_id)
    result = b"\x01" + b"".join(_text(s) for s in ("5", "Mac OS X", "13.1", "22C65", "MacBookPro13,2")) + b"\0"*4
    fields = [(0, struct.pack("!I", 25)), (1, struct.pack("!I", 26)),
              (2, device_uuid.bytes), (5, UUID(instance_id).bytes),
              (3, struct.pack("!Q", 0x80)), (4, struct.pack("!H", 32))]
    return result + b"".join(bytes([kind])+struct.pack("!H", len(data))+data for kind, data in fields)


@dataclass(repr=False)
class DataChannel:
    peer_guid: bytes
    local_guid: bytes
    source_port: int
    target_port: int
    peer_ssrc: int
    local_ssrc: int
    peer_start: int
    local_start: int
    receive_material: bytes
    send_material: bytes
    reply: bytes
    request: bytes
    highest_index: int | None = None
    seen: set | None = None
    send_index: int | None = None

    @staticmethod
    def wire_index(index, start):
        # Native IDSStreamEncryption initializes its *last* sequence to zero,
        # separately from the advertised start. A first sequence >= 0x8000 is
        # interpreted as preceding that zero: ROC is locally -1 (uint32 max).
        # After the first wrap it becomes zero. Keep chronological replay state
        # separate from this wire nonce quirk.
        return (index - (65536 if start >= 32768 else 0)) & ((1 << 48)-1)

    def encrypt(self, payload):
        if type(payload) is not bytes or len(payload) > 1300:
            raise RelayProtocolError("Invalid outgoing IDS datagram")
        index = self.local_start if self.send_index is None else self.send_index
        if index >= 1 << 48:
            raise RelayProtocolError("IDS stream counter exhausted")
        # Reserve before encryption/send. Lost packets must never reuse a nonce.
        self.send_index = index + 1
        udp = struct.pack("!HHHH", self.target_port, self.source_port, len(payload)+8, 0) + payload
        digest = checksum(b"\0"*32+struct.pack("!I",len(udp))+b"\0\0\0\x11"+udp) or 65535
        plain = b"\0"+udp[:6]+struct.pack("!H",digest)+udp[8:]
        return b"\xe0\0"+struct.pack("!HI",index & 65535,self.local_ssrc)+stream_transform(
            self.send_material,self.local_ssrc,self.wire_index(index,self.local_start),plain)

    def decrypt(self, packet):
        if len(packet) < 17 or packet[:2] != b"\xe0\0":
            raise RelayProtocolError("Invalid encrypted IDS datagram")
        sequence, ssrc = struct.unpack_from("!HI", packet, 2)
        if ssrc != self.peer_ssrc:
            raise RelayProtocolError("IDS datagram belongs to another channel")
        reference = self.peer_start if self.highest_index is None else self.highest_index
        rollover = reference >> 16
        if (reference & 65535) < 32768 and sequence - (reference & 65535) > 32768:
            rollover -= 1
        elif (reference & 65535) >= 32768 and (reference & 65535)-sequence > 32768:
            rollover += 1
        index = (rollover << 16) | sequence
        if index < 0 or index >= 1 << 48 or index < reference-511 or self.seen is not None and index in self.seen:
            raise RelayProtocolError("Replayed or expired IDS datagram")
        raw = stream_transform(self.receive_material, ssrc, self.wire_index(index,self.peer_start), packet[8:])
        if raw[0] != 0 or len(raw) < 9:
            raise RelayProtocolError("Unsupported IDS data compression")
        source, target, size, _ = struct.unpack_from("!HHHH", raw, 1)
        if (source, target) != (self.source_port, self.target_port) or size != len(raw)-1:
            raise RelayProtocolError("Invalid IDS data channel UDP header")
        if checksum(b"\0"*32+struct.pack("!I", size)+b"\0\0\0\x11"+raw[1:]) != 0:
            raise RelayProtocolError("IDS data channel UDP checksum mismatch")
        # Commit replay state only after inner report authentication by caller.
        return index, raw[9:]

    def mark_authenticated(self, index):
        self.highest_index = max(index, self.highest_index or 0)
        self.seen = {n for n in (self.seen or set()) if n >= self.highest_index-511}
        self.seen.add(index)


class UTunSession:
    def __init__(self, session_id, local_identity, peer_identity, device_id):
        self.session_name = str(session_id).upper().encode("ascii")
        self.local_identity, self.peer_identity = local_identity, peer_identity
        self.device_id, self.instance_id = device_id, str(uuid4())
        self.hello_sent = False
        self.channels = {}

    def receive_control(self, frame):
        data = decrypt_pair(frame, self.local_identity, self.peer_identity)
        if not data:
            raise RelayProtocolError("Empty IDS control message")
        replies = []
        if data[0] == 1 and not self.hello_sent:
            replies.append(hello(self.device_id, self.instance_id))
            self.hello_sent = True
        elif data[0] == 6:
            replies.append(self._setup_channel(data))
        summary = {"control_type": data[0], "bytes": len(data), "sender_signature_verified": True,
                   "channels_negotiated": len(self.channels)}
        return [encrypt_pair(p, self.local_identity, self.peer_identity) for p in replies], summary, data

    def _setup_channel(self, data):
        if len(data) < 24 or len(data) > 4096:
            raise RelayProtocolError("Invalid IDS channel setup")
        _, protocol, source, target, glen, local_len, alen, slen, nlen, ssrc, start, klen = struct.unpack_from("!BB7HIHH", data)
        if protocol != 17 or not 1025 <= source <= 65535 or not 1025 <= target <= 65535:
            raise RelayProtocolError("Unsupported IDS channel transport")
        if glen != 36 or local_len != 0 or not 1 <= alen <= 256 or klen != 60:
            raise RelayProtocolError("Invalid IDS channel parameters")
        lengths = (glen, local_len, alen, slen, nlen, klen)
        if sum(lengths)+24 != len(data):
            raise RelayProtocolError("Invalid IDS channel setup lengths")
        fields, pos = [], 24
        for size in lengths:
            fields.append(data[pos:pos+size])
            pos += size
        guid, _, account, service, name, material = fields
        UUID(guid.decode("ascii"))
        if service != b"com.apple.private.alloy.fmd" or name not in (self.session_name, self.session_name+b"-0"):
            raise RelayProtocolError("IDS channel is outside the selected session")
        if name in self.channels:
            channel = self.channels[name]
            if data != channel.request:
                raise RelayProtocolError("IDS channel parameters changed")
            return channel.reply
        if len(self.channels) >= 2:
            raise RelayProtocolError("Too many IDS channels")
        local_guid, own_material = str(uuid4()).upper().encode("ascii"), secrets.token_bytes(60)
        own_ssrc, own_start = secrets.randbits(32), secrets.randbits(16)
        reply = struct.pack("!BB7HIHH", 6, protocol, target, source, len(local_guid), len(guid),
            len(account), len(service), len(name), own_ssrc, own_start, 60)
        reply += local_guid + guid + account + service + name + own_material
        merged = bytes(a ^ b for a, b in zip(material, own_material))
        outgoing, incoming = (merged[:30], merged[30:]) if local_guid > guid else (merged[30:], merged[:30])
        self.channels[name] = DataChannel(guid, local_guid, source, target, ssrc, own_ssrc,
            start, own_start, incoming, outgoing, reply, data)
        return reply

    def decrypt_datagram(self, packet):
        if len(packet) < 8:
            raise RelayProtocolError("Truncated IDS encrypted packet")
        ssrc = struct.unpack_from("!I", packet, 4)[0]
        matches = [c for c in self.channels.values() if c.peer_ssrc == ssrc]
        if len(matches) != 1:
            raise RelayProtocolError("Unknown IDS encrypted channel")
        channel = matches[0]
        index, payload = channel.decrypt(packet)
        return channel, index, payload
