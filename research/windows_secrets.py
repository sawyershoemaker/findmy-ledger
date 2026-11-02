"""Current-user Windows DPAPI persistence for experimental Apple session state."""
import ctypes
import json
import os
from ctypes import wintypes
from pathlib import Path
from uuid import uuid4


class Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def transform(data: bytes, *, decrypt=False) -> bytes:
    if os.name != "nt":
        raise RuntimeError("This secret store requires Windows DPAPI")
    if not data or len(data) > 16 * 1024 * 1024:
        raise ValueError("Invalid session blob size")
    source_buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    source = Blob(len(data), ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_ubyte)))
    output = Blob()
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    operation = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    operation.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.POINTER(Blob),
                          ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    operation.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    try:
        # No LOCAL_MACHINE flag: bind protection to the current Windows user.
        if not operation(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(output)):
            raise OSError("Windows session protection failed")
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        ctypes.memset(source_buffer, 0, len(data))
        if output.pbData:
            ctypes.memset(output.pbData, 0, output.cbData)
            kernel.LocalFree(output.pbData)


def save_new(path, state):
    """Write only ciphertext and refuse to replace an existing session."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"format": "findmy-ledger-session-v1", "state": state}, separators=(",", ":")).encode()
    encrypted = transform(payload)
    with path.open("xb") as stream:
        stream.write(encrypted)
        stream.flush()
        os.fsync(stream.fileno())


def load(path):
    payload = json.loads(transform(Path(path).read_bytes(), decrypt=True))
    if payload.get("format") != "findmy-ledger-session-v1" or not isinstance(payload.get("state"), dict):
        raise ValueError("Unsupported protected session format")
    return payload["state"]


def save_atomic(path, state):
    """Replace mutable machine state atomically; temporary files contain ciphertext only."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid4().hex + ".tmp")
    try:
        save_new(temporary, state)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
