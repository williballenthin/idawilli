"""Build a minimal, valid 32-bit PE for use as a test fixture."""

import struct

CODE = bytes([0x55, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3])
IMAGE_BASE = 0x400000
TEXT_RVA = 0x1000
TEXT_SIZE = 0x200


def build_minimal_pe() -> bytes:
    code = CODE.ljust(TEXT_SIZE, b"\xcc")
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    opt = (
        struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            0x10B,
            1,
            0,
            TEXT_SIZE,
            0,
            0,
            TEXT_RVA,
            TEXT_RVA,
            0x2000,
            IMAGE_BASE,
            0x1000,
            0x200,
            4,
            0,
            0,
            0,
            4,
            0,
            0,
            0x2000,
            0x200,
            0,
            3,
            0,
            0x100000,
            0x1000,
            0x100000,
            0x1000,
            0,
            16,
        )
        + b"\x00" * 128
    )
    section = b".text".ljust(8, b"\x00") + struct.pack(
        "<IIIIIIHHI", TEXT_SIZE, TEXT_RVA, TEXT_SIZE, 0x200, 0, 0, 0, 0, 0x60000020
    )
    headers = (dos + b"PE\x00\x00" + coff + opt + section).ljust(0x200, b"\x00")
    return headers + code
