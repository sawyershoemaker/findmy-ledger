"""P-224 ECIES codec used by the selected-person report adapter.

Verified against a real authenticated People report on 2026-10-28. Account,
sender, relationship and timestamp checks live in key_probe/location_probe;
this module verifies the cryptographic envelope only.
"""
import hmac

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF


def decode_private_key(blob: bytes):
    if len(blob) != 85 or blob[0] != 4:
        raise ValueError("Expected a 57-byte P-224 public point and 28-byte private scalar")
    key = ec.derive_private_key(int.from_bytes(blob[57:], "big"), ec.SECP224R1())
    expected = key.public_key().public_bytes(serialization.Encoding.X962,
                                            serialization.PublicFormat.UncompressedPoint)
    if not hmac.compare_digest(expected, blob[:57]):
        raise ValueError("Public point does not match the private scalar")
    return key


def decrypt_report(payload: bytes, key):
    if not isinstance(key.curve, ec.SECP224R1):
        raise ValueError("Expected a P-224 report key")
    if len(payload) < 73 or len(payload) > 1_048_576 or payload[0] != 4:
        raise ValueError("Invalid report envelope")
    point = payload[:57]
    ephemeral = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP224R1(), point)
    shared = key.exchange(ec.ECDH(), ephemeral)
    material = X963KDF(algorithm=hashes.SHA256(), length=32, sharedinfo=point).derive(shared)
    # AESGCM rejects any changed ciphertext or authentication tag.
    return AESGCM(material[:16]).decrypt(material[16:], payload[57:], None)
