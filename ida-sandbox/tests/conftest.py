"""Shared fixtures for ida-sandbox tests."""

from dataclasses import dataclass, field

import pytest


# ---------------------------------------------------------------------------
# Lightweight mock objects that mimic the ida_domain API surface used by
# IdaSandbox, without requiring IDA Pro to be installed.
# ---------------------------------------------------------------------------


@dataclass
class MockFunction:
    start_ea: int
    size: int
    name: str = ""


@dataclass
class MockXref:
    from_ea: int
    to_ea: int
    type: "MockXrefType" = None
    is_call: bool = False
    is_jump: bool = False

    def __post_init__(self):
        if self.type is None:
            self.type = MockXrefType("Unknown")


@dataclass
class MockXrefType:
    name: str


class MockFunctions:
    """Mimics ``db.functions``."""

    def __init__(self, funcs: list[MockFunction]):
        self._funcs = funcs
        self._by_addr = {f.start_ea: f for f in funcs}
        self._disasm: dict[int, list[str]] = {}

    def __iter__(self):
        return iter(self._funcs)

    def get_name(self, func):
        return func.name

    def get_at(self, address):
        return self._by_addr.get(address)

    def get_disassembly(self, func):
        return self._disasm.get(func.start_ea, [])

    def set_disassembly(self, address, lines):
        self._disasm[address] = lines


class MockXrefs:
    """Mimics ``db.xrefs``."""

    def __init__(self):
        self._to: dict[int, list[MockXref]] = {}
        self._from: dict[int, list[MockXref]] = {}

    def to_ea(self, address):
        return self._to.get(address, [])

    def from_ea(self, address):
        return self._from.get(address, [])

    def add_to(self, address, xref: MockXref):
        self._to.setdefault(address, []).append(xref)

    def add_from(self, address, xref: MockXref):
        self._from.setdefault(address, []).append(xref)


class MockBytes:
    """Mimics ``db.bytes``."""

    def __init__(self, data: bytes = b"", base: int = 0):
        self._data = data
        self._base = base

    def get_bytes_at(self, address, size):
        offset = address - self._base
        if offset < 0 or offset >= len(self._data):
            return None
        return self._data[offset : offset + size]


@dataclass
class MockDatabase:
    """A lightweight stand-in for ``ida_domain.Database``."""

    functions: MockFunctions = field(default_factory=lambda: MockFunctions([]))
    xrefs: MockXrefs = field(default_factory=MockXrefs)
    bytes: MockBytes = field(default_factory=MockBytes)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_db():
    """Return a pre-populated MockDatabase with a small, predictable program."""
    funcs = [
        MockFunction(start_ea=0x401000, size=32, name="main"),
        MockFunction(start_ea=0x401100, size=16, name="helper"),
        MockFunction(start_ea=0x401200, size=8, name="cleanup"),
    ]
    functions = MockFunctions(funcs)
    functions.set_disassembly(0x401000, [
        "push rbp",
        "mov rbp, rsp",
        "call helper",
        "call cleanup",
        "xor eax, eax",
        "pop rbp",
        "ret",
    ])
    functions.set_disassembly(0x401100, [
        "push rbp",
        "mov rbp, rsp",
        "nop",
        "pop rbp",
        "ret",
    ])
    functions.set_disassembly(0x401200, [
        "ret",
    ])

    xrefs = MockXrefs()
    # main calls helper and cleanup
    xrefs.add_to(0x401100, MockXref(
        from_ea=0x401008, to_ea=0x401100,
        type=MockXrefType("call_near"), is_call=True,
    ))
    xrefs.add_to(0x401200, MockXref(
        from_ea=0x40100D, to_ea=0x401200,
        type=MockXrefType("call_near"), is_call=True,
    ))
    xrefs.add_from(0x401008, MockXref(
        from_ea=0x401008, to_ea=0x401100,
        type=MockXrefType("call_near"), is_call=True,
    ))
    xrefs.add_from(0x40100D, MockXref(
        from_ea=0x40100D, to_ea=0x401200,
        type=MockXrefType("call_near"), is_call=True,
    ))

    raw_bytes = bytes(range(48))  # 0x00..0x2F at base 0x401000
    mock_bytes = MockBytes(data=raw_bytes, base=0x401000)

    return MockDatabase(functions=functions, xrefs=xrefs, bytes=mock_bytes)
