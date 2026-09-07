"""Write a ZIP archive encrypted with traditional PKWARE (ZipCrypto) encryption.

The standard library can read such archives but cannot write them, so tests build
them here. Members are stored uncompressed.
"""

import struct
import zlib


def _crc32_byte(crc: int, byte: int) -> int:
    return zlib.crc32(bytes([byte]), crc ^ 0xFFFFFFFF) ^ 0xFFFFFFFF


class _Keys:
    def __init__(self, password: bytes):
        self.k0, self.k1, self.k2 = 0x12345678, 0x23456789, 0x34567890
        for b in password:
            self.update(b)

    def update(self, byte: int) -> None:
        self.k0 = _crc32_byte(self.k0, byte)
        self.k1 = ((self.k1 + (self.k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        self.k2 = _crc32_byte(self.k2, self.k1 >> 24)

    def stream_byte(self) -> int:
        t = (self.k2 | 2) & 0xFFFF
        return ((t * (t ^ 1)) >> 8) & 0xFF

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray()
        for c in data:
            out.append(c ^ self.stream_byte())
            self.update(c)
        return bytes(out)


def make_encrypted_zip(files: dict[str, bytes], password: str) -> bytes:
    body = bytearray()
    central = bytearray()
    for name, data in files.items():
        crc = zlib.crc32(data) & 0xFFFFFFFF
        header = bytes(range(11)) + bytes([(crc >> 24) & 0xFF])
        payload = _Keys(password.encode()).encrypt(header + data)
        raw_name = name.encode()
        offset = len(body)
        common = struct.pack(
            "<HHHHHIII", 20, 1, 0, 0, 0x21, crc, len(payload), len(data)
        )
        body += (
            b"PK\x03\x04"
            + common
            + struct.pack("<HH", len(raw_name), 0)
            + raw_name
            + payload
        )
        central += (
            b"PK\x01\x02"
            + struct.pack("<H", 20)
            + common
            + struct.pack("<HHHHHII", len(raw_name), 0, 0, 0, 0, 0, offset)
            + raw_name
        )
    eocd = b"PK\x05\x06" + struct.pack(
        "<HHHHIIH", 0, 0, len(files), len(files), len(central), len(body), 0
    )
    return bytes(body + central + eocd)
