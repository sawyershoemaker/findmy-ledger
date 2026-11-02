"""Separate pair-ec's six identity bytes from its informational version byte.

RustPush ids/user.rs checks validator[..6], then verifies the full ECDSA
signature. The pinned Onitrack receiver also compares the final byte to 0x0c,
although registration advertises NGM 13. Preserve its identity and signature
checks; normalize only that non-identity trailer for its existing decoder.
"""
from contextlib import contextmanager
import hmac


@contextmanager
def compatible_validator(ids, protocol, stats):
    original = protocol.decrypt_pair_ec

    def decode(envelope, *, receiver_identity, sender_identity):
        fields = protocol._parse_protobuf(envelope, "NGM outer message")
        validator = protocol._one_bytes(fields, 99, "NGM validator")
        stats["ngm_validation"] = {"validator_bytes": len(validator), "message_signature_verified": False}
        if len(validator) != 7:
            raise protocol.KeyAcquisitionError("NGM validator is malformed")
        receiver_device = protocol._load_ec_private_key(receiver_identity.get("device_private_key_pem"), "receiver NGM device key")
        receiver_prekey = protocol._load_ec_private_key(receiver_identity.get("pre_private_key_pem"), "receiver NGM prekey")
        expected = (protocol._public_x(sender_identity.device_public_key)[:2],
                    protocol._public_x(receiver_device.public_key())[:2],
                    protocol._public_x(receiver_prekey.public_key())[:2])
        diagnostic = {"validator_bytes": len(validator), "version_byte": validator[6],
                      "sender_prefix_matches": hmac.compare_digest(validator[:2], expected[0]),
                      "receiver_device_prefix_matches": hmac.compare_digest(validator[2:4], expected[1]),
                      "receiver_prekey_prefix_matches": hmac.compare_digest(validator[4:6], expected[2]),
                      "message_signature_verified": False}
        stats["ngm_validation"] = diagnostic
        normalized = b"".join(ids._proto_bytes(field, protocol._one_bytes(fields, field, "NGM field"))
                              for field in (1, 2, 3))
        normalized += ids._proto_bytes(99, validator[:6] + b"\x0c")
        plaintext = original(normalized, receiver_identity=receiver_identity, sender_identity=sender_identity)
        diagnostic["message_signature_verified"] = True
        return plaintext

    protocol.decrypt_pair_ec = decode
    try:
        yield
    finally:
        protocol.decrypt_pair_ec = original
