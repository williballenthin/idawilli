"""Shared fixtures for ida-sandbox tests."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest


# ---------------------------------------------------------------------------
# Lightweight mock objects that mimic the ida_domain API surface used by
# IdaSandbox, without requiring IDA Pro to be installed.
# ---------------------------------------------------------------------------


# --- Functions ---


@dataclass
class MockFunction:
    start_ea: int
    size: int
    name: str = ""


@dataclass
class MockXref:
    from_ea: int
    to_ea: int
    type: MockXrefType | None = None
    is_call: bool = False
    is_jump: bool = False

    def __post_init__(self) -> None:
        if self.type is None:
            self.type = MockXrefType("Unknown")


@dataclass
class MockXrefType:
    name: str


class MockFunctions:
    """Mimics ``db.functions``."""

    def __init__(self, funcs: list[MockFunction]) -> None:
        self._funcs = funcs
        self._by_addr: dict[int, MockFunction] = {f.start_ea: f for f in funcs}
        self._by_name: dict[str, MockFunction] = {f.name: f for f in funcs}
        self._disasm: dict[int, list[str]] = {}
        self._pseudocode: dict[int, list[str]] = {}
        self._signatures: dict[int, str | None] = {}
        self._callers: dict[int, list[MockFunction]] = {}
        self._callees: dict[int, list[MockFunction]] = {}
        self._flowcharts: dict[int, MockFlowChart] = {}
        self._comments: dict[int, str | None] = {}

    def __iter__(self):
        return iter(self._funcs)

    def get_name(self, func: MockFunction) -> str:
        return func.name

    def get_at(self, address: int) -> MockFunction | None:
        return self._by_addr.get(address)

    def get_function_by_name(self, name: str) -> MockFunction | None:
        return self._by_name.get(name)

    def get_disassembly(self, func: MockFunction) -> list[str]:
        return self._disasm.get(func.start_ea, [])

    def get_pseudocode(self, func: MockFunction) -> list[str]:
        if func.start_ea in self._pseudocode:
            return self._pseudocode[func.start_ea]
        raise RuntimeError("decompiler not available")

    def get_signature(self, func: MockFunction) -> str | None:
        return self._signatures.get(func.start_ea)

    def get_callers(self, func: MockFunction) -> list[MockFunction]:
        return self._callers.get(func.start_ea, [])

    def get_callees(self, func: MockFunction) -> list[MockFunction]:
        return self._callees.get(func.start_ea, [])

    def get_flowchart(self, func: MockFunction) -> MockFlowChart | None:
        return self._flowcharts.get(func.start_ea)

    def get_comment(self, func: MockFunction) -> str | None:
        return self._comments.get(func.start_ea)

    # --- test helpers ---

    def set_disassembly(self, address: int, lines: list[str]) -> None:
        self._disasm[address] = lines

    def set_pseudocode(self, address: int, lines: list[str]) -> None:
        self._pseudocode[address] = lines

    def set_signature(self, address: int, sig: str | None) -> None:
        self._signatures[address] = sig

    def set_callers(self, address: int, callers: list[MockFunction]) -> None:
        self._callers[address] = callers

    def set_callees(self, address: int, callees: list[MockFunction]) -> None:
        self._callees[address] = callees

    def set_flowchart(self, address: int, fc: MockFlowChart) -> None:
        self._flowcharts[address] = fc


# --- Cross-references ---


class MockXrefs:
    """Mimics ``db.xrefs``."""

    def __init__(self) -> None:
        self._to: dict[int, list[MockXref]] = {}
        self._from: dict[int, list[MockXref]] = {}

    def to_ea(self, address: int) -> list[MockXref]:
        return self._to.get(address, [])

    def from_ea(self, address: int) -> list[MockXref]:
        return self._from.get(address, [])

    def add_to(self, address: int, xref: MockXref) -> None:
        self._to.setdefault(address, []).append(xref)

    def add_from(self, address: int, xref: MockXref) -> None:
        self._from.setdefault(address, []).append(xref)


# --- Bytes ---


class MockBytes:
    """Mimics ``db.bytes``."""

    def __init__(self, data: bytes = b"", base: int = 0) -> None:
        self._data = data
        self._base = base
        self._cstrings: dict[int, str] = {}
        self._disasm: dict[int, str] = {}
        self._code_addrs: set[int] = set()
        self._data_addrs: set[int] = set()

    def get_bytes_at(self, address: int, size: int) -> bytes | None:
        offset = address - self._base
        if offset < 0 or offset >= len(self._data):
            return None
        return self._data[offset : offset + size]

    def get_cstring_at(self, address: int) -> str | None:
        return self._cstrings.get(address)

    def get_disassembly_at(self, address: int) -> str | None:
        return self._disasm.get(address)

    def is_code_at(self, address: int) -> bool:
        return address in self._code_addrs

    def is_data_at(self, address: int) -> bool:
        return address in self._data_addrs

    def find_binary_sequence(self, pattern: bytes) -> list[int]:
        results: list[int] = []
        for i in range(len(self._data) - len(pattern) + 1):
            if self._data[i : i + len(pattern)] == pattern:
                results.append(self._base + i)
        return results


# --- Strings ---


@dataclass
class MockStringType:
    name: str


@dataclass
class MockStringItem:
    address: int
    length: int
    type: MockStringType
    contents: bytes


class MockStrings:
    """Mimics ``db.strings``."""

    def __init__(self, items: list[MockStringItem] | None = None) -> None:
        self._items = items or []

    def __iter__(self):
        return iter(self._items)


# --- Segments ---


@dataclass
class MockSegment:
    start_ea: int
    end_ea: int
    perm: int
    _name: str = ""
    _class: str = ""
    _bitness: int = 64


class MockSegments:
    """Mimics ``db.segments``."""

    def __init__(self, segs: list[MockSegment] | None = None) -> None:
        self._segs = segs or []

    def __iter__(self):
        return iter(self._segs)

    def get_name(self, seg: MockSegment) -> str:
        return seg._name

    def get_size(self, seg: MockSegment) -> int:
        return seg.end_ea - seg.start_ea

    def get_class(self, seg: MockSegment) -> str:
        return seg._class

    def get_bitness(self, seg: MockSegment) -> int:
        return seg._bitness


# --- Names ---


class MockNames:
    """Mimics ``db.names``."""

    def __init__(self, entries: list[tuple[int, str]] | None = None) -> None:
        self._entries = entries or []
        self._by_addr: dict[int, str] = dict(self._entries)

    def __iter__(self):
        return iter(self._entries)

    def get_at(self, address: int) -> str | None:
        return self._by_addr.get(address)

    def demangle_name(self, name: str) -> str:
        # Trivial mock: strip a leading underscore
        if name.startswith("_Z"):
            return f"demangled({name})"
        return name


# --- Imports ---


@dataclass
class MockImportInfo:
    address: int
    name: str
    module_name: str
    ordinal: int


class MockImports:
    """Mimics ``db.imports``."""

    def __init__(self, imports: list[MockImportInfo] | None = None) -> None:
        self._imports = imports or []

    def get_all_imports(self) -> list[MockImportInfo]:
        return self._imports


# --- Entries ---


@dataclass
class MockEntryInfo:
    ordinal: int
    address: int
    name: str
    has_forwarder: bool = False
    forwarder_name: str = ""


class MockEntries:
    """Mimics ``db.entries``."""

    def __init__(self, entries: list[MockEntryInfo] | None = None) -> None:
        self._entries = entries or []

    def __iter__(self):
        return iter(self._entries)


# --- Instructions ---


@dataclass
class MockInstruction:
    ea: int
    size: int
    _mnemonic: str = ""
    _disassembly: str = ""
    _is_call: bool = False


class MockInstructions:
    """Mimics ``db.instructions``."""

    def __init__(self, insns: dict[int, MockInstruction] | None = None) -> None:
        self._insns = insns or {}

    def get_at(self, address: int) -> MockInstruction | None:
        return self._insns.get(address)

    def get_mnemonic(self, insn: MockInstruction) -> str:
        return insn._mnemonic

    def get_disassembly(self, insn: MockInstruction) -> str:
        return insn._disassembly

    def is_call_instruction(self, insn: MockInstruction) -> bool:
        return insn._is_call


# --- Comments ---


class MockComments:
    """Mimics ``db.comments``."""

    def __init__(self, comments: dict[int, str] | None = None) -> None:
        self._comments = comments or {}

    def get_at(self, address: int) -> str | None:
        return self._comments.get(address)


# --- FlowChart / BasicBlocks ---


@dataclass
class MockBasicBlock:
    start_ea: int
    end_ea: int
    _successors: list[MockBasicBlock] = field(default_factory=list)
    _predecessors: list[MockBasicBlock] = field(default_factory=list)

    def succs(self) -> list[MockBasicBlock]:
        return self._successors

    def preds(self) -> list[MockBasicBlock]:
        return self._predecessors


class MockFlowChart:
    """Mimics a FlowChart object."""

    def __init__(self, blocks: list[MockBasicBlock] | None = None) -> None:
        self._blocks = blocks or []

    def __iter__(self):
        return iter(self._blocks)

    def __len__(self) -> int:
        return len(self._blocks)


# --- Database ---


@dataclass
class MockDatabase:
    """A lightweight stand-in for ``ida_domain.Database``."""

    functions: MockFunctions = field(default_factory=lambda: MockFunctions([]))
    xrefs: MockXrefs = field(default_factory=MockXrefs)
    bytes: MockBytes = field(default_factory=MockBytes)
    strings: MockStrings = field(default_factory=MockStrings)
    segments: MockSegments = field(default_factory=MockSegments)
    names: MockNames = field(default_factory=MockNames)
    imports: MockImports = field(default_factory=MockImports)
    entries: MockEntries = field(default_factory=MockEntries)
    instructions: MockInstructions = field(default_factory=MockInstructions)
    comments: MockComments = field(default_factory=MockComments)

    # Database metadata
    path: str = "/mock/binary"
    module: str = "binary"
    architecture: str = "metapc"
    bitness: int = 64
    format: str = "ELF64"
    base_address: int = 0
    start_ip: int = 0x401060
    minimum_ea: int = 0x400000
    maximum_ea: int = 0x410000
    filesize: int = 65536
    md5: str = "d41d8cd98f00b204e9800998ecf8427e"
    sha256: str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    crc32: int = 0

    # Validity map
    _valid_eas: set[int] = field(default_factory=set)

    def is_valid_ea(self, address: int) -> bool:
        return address in self._valid_eas


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_db() -> MockDatabase:
    """Return a pre-populated MockDatabase with a small, predictable program."""

    # --- Functions ---
    main = MockFunction(start_ea=0x401000, size=32, name="main")
    helper = MockFunction(start_ea=0x401100, size=16, name="helper")
    cleanup = MockFunction(start_ea=0x401200, size=8, name="cleanup")
    funcs = [main, helper, cleanup]

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
    functions.set_disassembly(0x401200, ["ret"])
    functions.set_pseudocode(0x401000, [
        "int main(void) {",
        "  helper();",
        "  cleanup();",
        "  return 0;",
        "}",
    ])
    functions.set_signature(0x401000, "int __cdecl main(void)")
    functions.set_callers(0x401100, [main])
    functions.set_callees(0x401000, [helper, cleanup])

    # --- Flowchart for main: 2 blocks ---
    block0 = MockBasicBlock(start_ea=0x401000, end_ea=0x401010)
    block1 = MockBasicBlock(start_ea=0x401010, end_ea=0x401020)
    block0._successors = [block1]
    block1._predecessors = [block0]
    functions.set_flowchart(0x401000, MockFlowChart([block0, block1]))

    # --- Cross-references ---
    xrefs = MockXrefs()
    xrefs.add_to(0x401100, MockXref(
        from_ea=0x401008, to_ea=0x401100,
        type=MockXrefType("CALL_NEAR"), is_call=True,
    ))
    xrefs.add_to(0x401200, MockXref(
        from_ea=0x40100D, to_ea=0x401200,
        type=MockXrefType("CALL_NEAR"), is_call=True,
    ))
    xrefs.add_from(0x401008, MockXref(
        from_ea=0x401008, to_ea=0x401100,
        type=MockXrefType("CALL_NEAR"), is_call=True,
    ))
    xrefs.add_from(0x40100D, MockXref(
        from_ea=0x40100D, to_ea=0x401200,
        type=MockXrefType("CALL_NEAR"), is_call=True,
    ))

    # --- Bytes ---
    raw_bytes = bytes(range(48))  # 0x00..0x2F at base 0x401000
    mock_bytes = MockBytes(data=raw_bytes, base=0x401000)
    mock_bytes._cstrings[0x402000] = "Hello, %s!\n"
    mock_bytes._disasm[0x401000] = "push rbp"
    mock_bytes._disasm[0x401001] = "mov rbp, rsp"
    mock_bytes._code_addrs = {0x401000, 0x401001, 0x401100}
    mock_bytes._data_addrs = {0x402000}

    # --- Strings ---
    strings = MockStrings([
        MockStringItem(address=0x402000, length=12, type=MockStringType("C"),
                       contents=b"Hello, %s!\n"),
        MockStringItem(address=0x402010, length=13, type=MockStringType("C"),
                       contents=b"result = %d\n"),
    ])

    # --- Segments ---
    segments = MockSegments([
        MockSegment(start_ea=0x401000, end_ea=0x402000, perm=5,
                    _name=".text", _class="CODE", _bitness=64),
        MockSegment(start_ea=0x402000, end_ea=0x403000, perm=4,
                    _name=".rodata", _class="DATA", _bitness=64),
    ])

    # --- Names ---
    names = MockNames([
        (0x401000, "main"),
        (0x401100, "helper"),
        (0x401200, "cleanup"),
        (0x402000, "aHelloS"),
    ])

    # --- Imports ---
    imports = MockImports([
        MockImportInfo(address=0x404000, name="printf", module_name="libc.so.6", ordinal=0),
        MockImportInfo(address=0x404008, name="__cxa_finalize", module_name="libc.so.6", ordinal=1),
    ])

    # --- Entries ---
    entries = MockEntries([
        MockEntryInfo(ordinal=0, address=0x401060, name="_start"),
    ])

    # --- Instructions ---
    instructions = MockInstructions({
        0x401000: MockInstruction(ea=0x401000, size=1, _mnemonic="push",
                                  _disassembly="push rbp", _is_call=False),
        0x401008: MockInstruction(ea=0x401008, size=5, _mnemonic="call",
                                  _disassembly="call helper", _is_call=True),
    })

    # --- Comments ---
    comments = MockComments({
        0x401000: "function prologue",
    })

    # --- Validity ---
    valid_eas = {0x401000, 0x401100, 0x401200, 0x402000, 0x404000}

    return MockDatabase(
        functions=functions,
        xrefs=xrefs,
        bytes=mock_bytes,
        strings=strings,
        segments=segments,
        names=names,
        imports=imports,
        entries=entries,
        instructions=instructions,
        comments=comments,
        _valid_eas=valid_eas,
    )
