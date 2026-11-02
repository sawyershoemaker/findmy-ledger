"""Legacy IDS pair-v2 encryption required by UTun control channels.

Wire algorithms are RSA-OAEP/SHA1, AES-128-CTR, and ECDSA/SHA1. These are
protocol compatibility choices, never defaults for newly designed encryption.
Every decode requires the selected sender's directory signing key.
"""
from dataclasses import dataclass
import hashlib
import hmac
import secrets
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .live_relay import RelayProtocolError

IV = b"\0" * 15 + b"\x01"
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)


@dataclass(frozen=True, repr=False)
class PairIdentity:
    signing: object
    encryption: object

    def digest(self):
        signing = self.signing.public_key() if hasattr(self.signing, "public_key") else self.signing
        encryption = self.encryption.public_key() if hasattr(self.encryption, "public_key") else self.encryption
        point = signing.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        der = encryption.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
        return hashlib.sha256(struct.pack("!H", len(point))+point+struct.pack("!H", len(der))+der).digest()


def _der_item(data, position, tag):
    if position + 2 > len(data) or data[position] != tag:
        raise RelayProtocolError("Invalid pair public identity DER")
    length = data[position+1]
    position += 2
    if length & 128:
        count = length & 127
        if not 1 <= count <= 2 or position+count > len(data):
            raise RelayProtocolError("Invalid pair identity DER length")
        length = int.from_bytes(data[position:position+count], "big")
        position += count
    if position+length > len(data):
        raise RelayProtocolError("Truncated pair identity DER")
    return data[position:position+length], position+length


def public_identity(encoded):
    if type(encoded) is not bytes or not 128 <= len(encoded) <= 1024:
        raise RelayProtocolError("Invalid pair public identity")
    sequence, end = _der_item(encoded, 0, 0x30)
    if end != len(encoded):
        raise RelayProtocolError("Trailing pair identity data")
    sign, pos = _der_item(sequence, 0, 0x81)
    enc, pos = _der_item(sequence, pos, 0x82)
    if pos != len(sequence) or len(sign) != 67 or int.from_bytes(sign[:2], "big") != 65:
        raise RelayProtocolError("Invalid pair signing identity")
    if len(enc) < 2 or int.from_bytes(enc[:2], "big") != len(enc)-2:
        raise RelayProtocolError("Invalid pair encryption identity")
    signing = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), sign[2:])
    encryption = serialization.load_der_public_key(enc[2:])
    if not isinstance(encryption, rsa.RSAPublicKey) or encryption.key_size not in (1280, 2048):
        raise RelayProtocolError("Unsupported pair encryption identity")
    return PairIdentity(signing, encryption)


def private_identity(saved):
    signing = serialization.load_pem_private_key(saved["signing_private_key_pem"].encode("ascii"), None)
    encryption = serialization.load_pem_private_key(saved["encryption_private_key_pem"].encode("ascii"), None)
    if (not isinstance(signing, ec.EllipticCurvePrivateKey) or not isinstance(signing.curve, ec.SECP256R1)
            or not isinstance(encryption, rsa.RSAPrivateKey) or encryption.key_size not in (1280, 2048)):
        raise RelayProtocolError("Unsupported local pair identity")
    return PairIdentity(signing, encryption)


def decrypt_pair(packet, receiver, sender):
    if type(packet) is not bytes or not 4 <= len(packet) <= 65535 or packet[0] != 2:
        raise RelayProtocolError("Invalid pair envelope")
    length = int.from_bytes(packet[1:3], "big")
    if length+4 > len(packet) or packet[3+length] + length+4 != len(packet):
        raise RelayProtocolError("Invalid pair envelope lengths")
    body, signature = packet[3:3+length], packet[4+length:]
    sender.signing.verify(signature, body, ec.ECDSA(hashes.SHA1()))
    rsa_length = receiver.encryption.key_size // 8
    if len(body) < rsa_length:
        raise RelayProtocolError("Truncated pair RSA envelope")
    secret = receiver.encryption.decrypt(body[:rsa_length], OAEP)
    if not 16 <= len(secret) <= 116 or len(body) > rsa_length and len(secret) != 116:
        raise RelayProtocolError("Invalid pair key envelope")
    decryptor = Cipher(algorithms.AES(secret[:16]), modes.CTR(IV)).decryptor()
    plain = decryptor.update(secret[16:] + body[rsa_length:]) + decryptor.finalize()
    binding = hmac.digest(secret[:11], plain+b"\x02"+sender.digest()+receiver.digest(), hashlib.sha256)[:5]
    if not hmac.compare_digest(binding, secret[11:16]):
        raise RelayProtocolError("Pair key identity binding failed")
    return plain


def encrypt_pair(plain, sender, receiver):
    if type(plain) is not bytes or len(plain) > 64000:
        raise RelayProtocolError("Pair plaintext exceeds limit")
    random = secrets.token_bytes(11)
    key = random + hmac.digest(random, plain+b"\x02"+sender.digest()+receiver.digest(), hashlib.sha256)[:5]
    encryptor = Cipher(algorithms.AES(key), modes.CTR(IV)).encryptor()
    encrypted = encryptor.update(plain) + encryptor.finalize()
    body = receiver.encryption.encrypt(key+encrypted[:100], OAEP) + encrypted[100:]
    signature = sender.signing.sign(body, ec.ECDSA(hashes.SHA1()))
    return b"\x02" + struct.pack("!H", len(body)) + body + bytes([len(signature)]) + signature
