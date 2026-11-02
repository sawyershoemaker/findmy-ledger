"""Extract only the pinned x86_64 CoreADI slice from Apple's local pkg Payload."""
import argparse
import hashlib
import struct
import subprocess
from pathlib import Path

MEMBER = "./System/Library/PrivateFrameworks/CoreADI.framework/Versions/A/CoreADI"
EXPECTED_SHA256 = "2eafc3c79c7f41a8afbfbeaaf23ee5dab5ad5bda55ec8e54dbc0ddf1d20ce630"


def extract(payload, output):
    # Read the one archive member as bytes; never materialize archive paths or symlinks.
    result = subprocess.run(["tar.exe", "-xOf", str(payload), MEMBER], capture_output=True, check=True, timeout=30)
    data = result.stdout
    magic, count = struct.unpack_from(">II", data)
    if magic != 0xCAFEBABE or not 1 <= count <= 8:
        raise ValueError("Unexpected universal Mach-O header")
    for index in range(count):
        cpu, _, offset, size, _ = struct.unpack_from(">IIIII", data, 8 + index * 20)
        if cpu == 0x01000007:
            binary = data[offset:offset + size]
            if hashlib.sha256(binary).hexdigest() != EXPECTED_SHA256:
                raise ValueError("CoreADI slice hash mismatch")
            path = Path(output)
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                if hashlib.sha256(path.read_bytes()).hexdigest() != EXPECTED_SHA256:
                    raise ValueError("Existing destination is a different file")
            else:
                with path.open("xb") as stream:
                    stream.write(binary)
            return len(binary)
    raise ValueError("No x86_64 CoreADI slice")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(f"Verified CoreADI slice: {extract(args.payload, args.output)} bytes")
