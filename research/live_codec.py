"""FindMyMessaging's plist codec, recovered from public Apple build 23B85.

This module has no network or account access. It does not establish a Live
session or authenticate a datagram; callers must authenticate the transport
and bind it to the selected participant before accepting its contents.

Evidence and the remaining transport work are recorded in docs/live-protocol.md.
"""
from dataclasses import dataclass
from enum import IntEnum
import base64
import math
import plistlib
from uuid import UUID


MAX_MESSAGE_BYTES = 1024 * 1024
MAX_DESTINATION_BYTES = 4096


class CodecError(ValueError):
    """Invalid or unsupported native message (never includes its contents)."""


class ControlType(IntEnum):
    HEARTBEAT = -1
    HEARTBEAT_REPLY = -2
    SHUTTING_DOWN = -3


class BeaconMessageType(IntEnum):
    LOCATION = 0


class DestinationType(IntEnum):
    EMAIL = 0
    PHONE_NUMBER = 1
    APS_TOKEN = 2
    SELF_TOKEN = 3
    DEVICE = 4
    SESSION = 5


@dataclass(frozen=True, repr=False)
class SessionMessage:
    type: int
    identifier: UUID
    payload: object
    version: int = 1


def _load(data):
    if type(data) is not bytes or not 8 <= len(data) <= MAX_MESSAGE_BYTES:
        raise CodecError("Invalid plist size or type")
    if not data.startswith(b"bplist00"):
        raise CodecError("Expected a binary property list")
    try:
        return plistlib.loads(data, fmt=plistlib.FMT_BINARY)
    except Exception:
        raise CodecError("Invalid binary property list") from None


def _dump(value):
    try:
        encoded = plistlib.dumps(value, fmt=plistlib.FMT_BINARY, sort_keys=False)
    except Exception:
        raise CodecError("Value cannot be encoded as a property list") from None
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise CodecError("Encoded property list exceeds the message limit")
    return encoded


def _message_type(value):
    # Native control messages occupy the negative Int32 range -1 through -3.
    # The application codec currently recognizes BeaconMessageType.LOCATION.
    if type(value) is not int or not -3 <= value <= 0x7fffffff:
        raise CodecError("Invalid session message type")
    return value


def encode_message(message):
    if not isinstance(message, SessionMessage):
        raise CodecError("Expected a session message")
    message_type = _message_type(message.type)
    if type(message.version) is not int or message.version != 1:
        raise CodecError("Unsupported session message version")
    if not isinstance(message.identifier, UUID):
        raise CodecError("Invalid session message identifier")
    if message_type < 0 and message.payload != "":
        raise CodecError("Control messages require the native empty payload")
    # Foundation encodes the generic payload in a one-element array so a
    # scalar can be represented at the plist root; P contains those bytes.
    return _dump({"T": message_type, "V": 1,
                  "I": str(message.identifier).upper(),
                  "P": _dump([message.payload])})


def decode_message(data):
    value = _load(data)
    if type(value) is not dict or set(value) != {"T", "V", "I", "P"}:
        raise CodecError("Invalid session message envelope")
    message_type = _message_type(value["T"])
    if type(value["V"]) is not int or value["V"] != 1:
        raise CodecError("Unsupported session message version")
    identifier = value["I"]
    if type(identifier) is not str or len(identifier) != 36:
        raise CodecError("Invalid session message identifier")
    try:
        parsed_id = UUID(identifier)
    except ValueError:
        raise CodecError("Invalid session message identifier") from None
    if str(parsed_id) != identifier.lower():
        raise CodecError("Invalid session message identifier")
    payload = _load(value["P"])
    if type(payload) is not list or len(payload) != 1:
        raise CodecError("Expected one wrapped payload")
    if message_type < 0 and payload[0] != "":
        raise CodecError("Unexpected control message payload")
    return SessionMessage(message_type, parsed_id, payload[0])


def encode_beacon_context(destination_type, destination):
    if not isinstance(destination_type, int) or type(destination_type) is bool:
        raise CodecError("Invalid destination type")
    try:
        destination_type = DestinationType(destination_type)
    except (ValueError, TypeError):
        raise CodecError("Invalid destination type") from None
    if type(destination) is not str or not destination or "\x00" in destination:
        raise CodecError("Invalid destination")
    if len(destination.encode("utf-8")) > MAX_DESTINATION_BYTES:
        raise CodecError("Destination exceeds the size limit")
    return _dump([1, {"type": int(destination_type), "destination": destination}])


def location_response(message):
    """Adapt native plist Data to the existing secure-report decoder's JSON shape.

    This does not authenticate anything. The report decoder must still match
    the selected advertised ID, verify AES-GCM, and check the inner participant
    and source timestamp. The outer locationTs never supplies observation time.
    """
    if (not isinstance(message, SessionMessage) or type(message.type) is not int
            or message.type != BeaconMessageType.LOCATION or type(message.version) is not int or message.version != 1):
        raise CodecError("Expected a native location message")
    payload = message.payload
    if type(payload) is not dict or not {"id", "locationInfo"} <= set(payload):
        raise CodecError("Invalid native location payload")
    if set(payload) - {"id", "keyType", "mode", "locationInfo"}:
        raise CodecError("Unsupported native location fields")
    if type(payload["id"]) is not bytes or len(payload["id"]) != 32:
        raise CodecError("Invalid advertised identifier")
    if "keyType" in payload and type(payload["keyType"]) is not int:
        raise CodecError("Invalid native key type")
    if "mode" in payload and (type(payload["mode"]) is not str or len(payload["mode"]) > 64):
        raise CodecError("Invalid native location mode")
    infos = payload["locationInfo"]
    if type(infos) is not list or len(infos) > 256:
        raise CodecError("Invalid native report list")
    rows, total = [], 0
    for info in infos:
        if type(info) is not dict or set(info) - {"location", "locationTs", "fmt"}:
            raise CodecError("Unsupported native report fields")
        data, timestamp = info.get("location"), info.get("locationTs")
        if type(data) is not bytes or not 1 <= len(data) <= MAX_MESSAGE_BYTES:
            raise CodecError("Invalid encrypted native report")
        total += len(data)
        if total > MAX_MESSAGE_BYTES:
            raise CodecError("Native report batch exceeds the size limit")
        if type(timestamp) not in (int, float) or not math.isfinite(timestamp):
            raise CodecError("Invalid outer report timestamp")
        fmt = info.get("fmt", 0)
        if type(fmt) is not int or not 0 <= fmt <= 0x7fffffff:
            raise CodecError("Invalid native report format")
        rows.append({"location": base64.b64encode(data).decode("ascii"), "locationTs": timestamp, "fmt": fmt})
    return {"locationPayload": [{"id": base64.b64encode(payload["id"]).decode("ascii"), "locationInfo": rows}]}
