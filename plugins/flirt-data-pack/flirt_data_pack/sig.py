"""Minimal FLIRT signature file builder for testing."""

import struct


def build_dummy_sig(library_name: str = "dummy") -> bytes:
    """Build a minimal FLIRT .sig file with zero functions.

    The file has a valid header that IDA recognises as a signature file, but
    contains no patterns. Useful for testing the installation mechanism without
    needing a real signature database.
    """
    magic = b"IDASGN"
    version = 10
    processor_id = 0  # METAPC
    file_types = 0xFFFFFFFF
    os_types = 0xFFFF
    app_types = 0xFFFF
    features = 0
    old_n_functions = 0
    crc16 = 0
    ctype = b"\x00"
    lib_name = library_name.encode("ascii") + b"\x00"
    alt_ctype_crc = 0
    n_functions = 0
    pattern_size = 32

    buf = bytearray()
    buf += magic
    buf += struct.pack("<B", version)
    buf += struct.pack("<B", processor_id)
    buf += struct.pack("<I", file_types)
    buf += struct.pack("<H", os_types)
    buf += struct.pack("<H", app_types)
    buf += struct.pack("<H", features)
    buf += struct.pack("<H", old_n_functions)
    buf += struct.pack("<H", crc16)
    buf += ctype
    buf += lib_name
    buf += struct.pack("<H", alt_ctype_crc)
    buf += struct.pack("<I", n_functions)
    buf += struct.pack("<H", pattern_size)
    return bytes(buf)
