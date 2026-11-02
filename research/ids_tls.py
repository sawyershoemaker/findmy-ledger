"""Verified Apple service TLS with the additional official Apple G3 root."""
import hashlib
import ssl
from functools import lru_cache
from pathlib import Path

ROOT_SHA256 = "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179"


def new_trust_context():
    from findmy.util.tls import _verified_root
    pem = (Path(__file__).parent / "certificates/apple-root-g3.pem").read_text(encoding="ascii")
    if hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest() != ROOT_SHA256:
        raise ValueError("Unexpected Apple G3 root certificate")
    context = ssl.create_default_context()
    context.load_verify_locations(cadata=_verified_root() + pem)
    return context


@lru_cache(maxsize=1)
def trust_context():
    return new_trust_context()
