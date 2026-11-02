"""Run a pinned IOKit encoding routine under Unicorn, never as a native DLL.

The separately obtained apple-gen assembly is linked locally with no imports.
This wrapper exposes only a bounded bytes-to-bytes operation with no IO hooks.
"""
import hashlib
import struct
from pathlib import Path

ENCODER_SHA256 = "e92aa56b157ac6e914fe008a1248bf098bd48b8d0fcba3747124f25e2dcb55cf"


def encode(binary_path, data):
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
    from unicorn.x86_const import UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RSP, UC_X86_REG_RAX, UC_X86_REG_RIP
    if not isinstance(data, bytes) or not 1 <= len(data) <= 64:
        raise ValueError("Unexpected IOKit input size")
    binary = Path(binary_path).read_bytes()
    if hashlib.sha256(binary).hexdigest() != ENCODER_SHA256:
        raise ValueError("Unexpected IOKit encoder binary")
    pe = struct.unpack_from("<I", binary, 0x3c)[0]
    count, optional_size = struct.unpack_from("<H", binary, pe + 6)[0], struct.unpack_from("<H", binary, pe + 20)[0]
    optional = pe + 24
    base = struct.unpack_from("<Q", binary, optional + 24)[0]
    size, headers = struct.unpack_from("<II", binary, optional + 56)
    mapped = bytearray(size)
    mapped[:headers] = binary[:headers]
    for index in range(count):
        at = optional + optional_size + 40 * index
        virtual_size, rva, raw_size, raw_at = struct.unpack_from("<IIII", binary, at + 8)
        mapped[rva:rva + raw_size] = binary[raw_at:raw_at + raw_size]
    machine = Uc(UC_ARCH_X86, UC_MODE_64)
    machine.mem_map(base, size)
    machine.mem_write(base, bytes(mapped))
    machine.mem_map(0x200000, 0x10000)
    machine.mem_map(0x400000, 0x100000)
    source, output, stack, stop = 0x201000, 0x202000, 0x4ff008, 0x200000
    machine.mem_write(source, data)
    machine.mem_write(stack, struct.pack("<Q", stop))
    for register, value in ((UC_X86_REG_RDI, source), (UC_X86_REG_RSI, len(data)),
                            (UC_X86_REG_RDX, output), (UC_X86_REG_RSP, stack)):
        machine.reg_write(register, value)
    machine.emu_start(base + 0x11000, stop, timeout=5_000_000, count=10_000_000)
    if machine.reg_read(UC_X86_REG_RIP) != stop or machine.reg_read(UC_X86_REG_RAX) != 0:
        raise ValueError("IOKit encoder failed or exceeded its bound")
    return bytes(machine.mem_read(output, 17))
