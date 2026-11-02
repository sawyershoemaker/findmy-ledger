"""Authenticate native Live reports; transport checksums never establish identity."""
import base64
import plistlib
from uuid import UUID, uuid4

from .live_codec import SessionMessage, encode_message
from .location_probe import LocationReportError, decoded_observation
from .report_codec import decrypt_report


def heartbeat(kind):
    if kind not in (-1, -2, -3):
        raise ValueError("Invalid heartbeat type")
    return encode_message(SessionMessage(kind, uuid4(), ""))


def decode(payload, advertised_id, private_key, fm_id, *, received_at):
    if type(payload) is not bytes or not 1 <= len(payload) <= 65536:
        raise LocationReportError("Invalid Live payload size")
    try:
        message = plistlib.loads(payload)
        if (type(message) is not dict or type(message.get("V")) is not int or message["V"] != 1
                or type(message.get("T")) is not int or type(message.get("I")) is not str):
            raise ValueError()
        UUID(message["I"])
        kind = message["T"]
        if kind in (-1, -2, -3):
            if type(message.get("P")) is not bytes or plistlib.loads(message["P"]) != [""]:
                raise ValueError()
            return kind, [], {"authenticated_reports": 0, "control_id": message["I"]}
        if kind != 0 or type(message.get("P")) is not bytes:
            raise ValueError()
        rows = plistlib.loads(message["P"])
        if type(rows) is not list or len(rows) > 32:
            raise ValueError()
        identifier = base64.b64decode(advertised_id, validate=True)
        observations, authenticated = {}, 0
        for row in rows:
            if type(row) is not dict or row.get("id") != identifier:
                continue
            infos = row.get("locationInfo")
            if type(infos) is not list or len(infos) > 64:
                raise ValueError()
            for info in infos:
                if type(info) is not dict:
                    raise ValueError()
                if info.get("fmt", 0) != 0:
                    continue
                encrypted = info.get("location")
                if type(encrypted) is not bytes or len(encrypted) > 65536:
                    raise ValueError()
                observation = decoded_observation(decrypt_report(encrypted, private_key), fm_id)
                authenticated += 1
                stamp = observation["observed_at"]
                # Preserve delayed history up to one day, never fabricate freshness.
                if not -300 <= received_at - stamp <= 86400:
                    continue
                if stamp in observations and observations[stamp] != observation:
                    raise ValueError()
                observations[stamp] = observation
        return kind, [observations[t] for t in sorted(observations)], {"authenticated_reports": authenticated}
    except Exception:
        raise LocationReportError("Live report or envelope verification failed") from None
