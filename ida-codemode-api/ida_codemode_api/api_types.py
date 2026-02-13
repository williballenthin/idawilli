"""Authoritative type declarations for :mod:`ida_codemode_api`.

This module is the single source of truth for API data types and function
signatures. It serves two consumers:

- the runtime implementation (:mod:`ida_codemode_api.api`) via imports
- Monty static type checking via ``TYPE_STUBS`` (the full file text)

Every API function returns either a success payload or :class:`ApiError`.
Errors are signaled by presence of the ``error`` key.
"""

from __future__ import annotations

from typing import Literal, TypedDict


class DatabaseMetadata(TypedDict):
    input_file_path: str
    module: str
    architecture: str
    bitness: int
    format: str
    base_address: int
    entry_point: int
    minimum_ea: int
    maximum_ea: int
    input_file_size: int
    input_file_md5: str
    input_file_sha256: str


class FunctionFlags(TypedDict):
    noreturn: bool
    library: bool
    thunk: bool


class FunctionInfo(TypedDict):
    address: int
    name: str
    size: int
    signature: str
    flags: FunctionFlags
    comment: str
    repeatable_comment: str


class NamedAddress(TypedDict):
    address: int
    name: str


class BasicBlockInfo(TypedDict):
    start: int
    end: int
    successors: list[int]
    predecessors: list[int]


class XrefToInfo(TypedDict):
    from_address: int
    type: str
    is_call: bool
    is_jump: bool


class XrefFromInfo(TypedDict):
    to_address: int
    type: str
    is_call: bool
    is_jump: bool


class StringInfo(TypedDict):
    address: int
    length: int
    type: str
    value: str


SegmentInfo = TypedDict(
    "SegmentInfo",
    {
        "name": str,
        "start": int,
        "end": int,
        "size": int,
        "permissions": int,
        "class": str,
        "bitness": int,
    },
)


class ImportInfo(TypedDict):
    address: int
    name: str
    module: str
    ordinal: int


class EntryPointInfo(TypedDict):
    ordinal: int
    address: int
    name: str
    forwarder: str | None


class InstructionInfo(TypedDict):
    address: int
    size: int
    mnemonic: str
    disassembly: str
    is_call: bool


AddressType = Literal["code", "data", "unknown", "invalid"]


class ApiError(TypedDict):
    error: str


class GetFunctionsOk(TypedDict):
    functions: list[FunctionInfo]


class GetFunctionDisassemblyAtOk(TypedDict):
    disassembly: list[str]


class DecompileFunctionAtOk(TypedDict):
    pseudocode: list[str]


class GetCallersAtOk(TypedDict):
    callers: list[NamedAddress]


class GetCalleesAtOk(TypedDict):
    callees: list[NamedAddress]


class GetBasicBlocksAtOk(TypedDict):
    basic_blocks: list[BasicBlockInfo]


class GetXrefsToAtOk(TypedDict):
    xrefs: list[XrefToInfo]


class GetXrefsFromAtOk(TypedDict):
    xrefs: list[XrefFromInfo]


class GetStringsOk(TypedDict):
    strings: list[StringInfo]


class GetStringAtOk(TypedDict):
    string: str


class GetSegmentsOk(TypedDict):
    segments: list[SegmentInfo]


class GetNamesOk(TypedDict):
    names: list[NamedAddress]


class GetNameAtOk(TypedDict):
    name: str


class DemangleNameOk(TypedDict):
    demangled_name: str


class GetImportsOk(TypedDict):
    imports: list[ImportInfo]


class GetEntriesOk(TypedDict):
    entries: list[EntryPointInfo]


class GetBytesAtOk(TypedDict):
    bytes: list[int]


class FindBytesOk(TypedDict):
    addresses: list[int]


class GetDisassemblyAtOk(TypedDict):
    disassembly: str


class GetAddressTypeOk(TypedDict):
    address_type: AddressType


class GetCommentAtOk(TypedDict):
    comment: str


class HelpOk(TypedDict):
    documentation: str


HelpResult = HelpOk | ApiError
GetDatabaseMetadataResult = DatabaseMetadata | ApiError
GetFunctionsResult = GetFunctionsOk | ApiError
GetFunctionByNameResult = FunctionInfo | ApiError
GetFunctionAtResult = FunctionInfo | ApiError
GetFunctionDisassemblyAtResult = GetFunctionDisassemblyAtOk | ApiError
DecompileFunctionAtResult = DecompileFunctionAtOk | ApiError
GetCallersAtResult = GetCallersAtOk | ApiError
GetCalleesAtResult = GetCalleesAtOk | ApiError
GetBasicBlocksAtResult = GetBasicBlocksAtOk | ApiError
GetXrefsToAtResult = GetXrefsToAtOk | ApiError
GetXrefsFromAtResult = GetXrefsFromAtOk | ApiError
GetStringsResult = GetStringsOk | ApiError
GetStringAtResult = GetStringAtOk | ApiError
GetSegmentsResult = GetSegmentsOk | ApiError
GetNamesResult = GetNamesOk | ApiError
GetNameAtResult = GetNameAtOk | ApiError
DemangleNameResult = DemangleNameOk | ApiError
GetImportsResult = GetImportsOk | ApiError
GetEntriesResult = GetEntriesOk | ApiError
GetBytesAtResult = GetBytesAtOk | ApiError
FindBytesResult = FindBytesOk | ApiError
GetDisassemblyAtResult = GetDisassemblyAtOk | ApiError
GetInstructionAtResult = InstructionInfo | ApiError
GetAddressTypeResult = GetAddressTypeOk | ApiError
GetCommentAtResult = GetCommentAtOk | ApiError


def help(api: str) -> HelpResult:
    """Extensive documentation for a specific API callback.

    Use this for progressive disclosure when you need the full docs for one
    callback, including argument semantics, return payload shape, and examples.
    See also `get_functions`, `get_function_at`, and `get_comment_at`.

    Args:
        api: Callback name to describe, such as `"get_function_at"`.

    Returns:
        Success payload `{documentation: str}` containing the callback
        signature and full declaration docstring, or `{"error": str}`.

    Errors:
        - Callback name is empty.
        - Callback name does not match any available API function.
        - Callback documentation is unavailable.

    Example success payload:
        {
            "documentation": "get_function_at(address: int) -> {address: int, name: str, size: int}\\n\\nFunction descriptor for a function start address.\\n...",
        }"""
    raise NotImplementedError


def get_database_metadata() -> GetDatabaseMetadataResult:
    """Database-wide metadata for the currently opened database.

    Call this first when you need global context such as architecture, entry
    point, and the valid address range before querying functions, bytes, or
    symbols. See also `get_segments`, `get_entries`, and `get_functions`.

    Args:
        None.

    Returns:
        Success payload
        `{input_file_path: str, module: str, architecture: str, bitness: int, format: str,
        base_address: int, entry_point: int, minimum_ea: int, maximum_ea: int,
        input_file_size: int, input_file_md5: str, input_file_sha256: str}` or `{"error": str}`.

    Errors:
        - Database metadata could not be read from the open database.

    Example success payload:
        {
            "input_file_path": "/tmp/sample.exe",
            "module": "sample.exe",
            "architecture": "metapc",
            "bitness": 32,
            "format": "PE",
            "base_address": 4194304,
            "entry_point": 4198400,
            "minimum_ea": 4194304,
            "maximum_ea": 4259840,
            "input_file_size": 57344,
            "input_file_md5": "d41d8cd98f00b204e9800998ecf8427e",
            "input_file_sha256": "4f9f...e3f1a",
        }"""
    raise NotImplementedError


def get_functions() -> GetFunctionsResult:
    """All discovered function descriptors.

    Use this to enumerate function entry points before calling per-function APIs.
    See also `get_function_by_name`, `get_function_at`, and `get_callers_at`.

    Args:
        None.

    Returns:
        Success payload `{functions: list[{address: int, name: str, size: int, signature: str,
        flags: {noreturn: bool, library: bool, thunk: bool}, comment: str,
        repeatable_comment: str}]}` or `{"error": str}`.

    Errors:
        - Function enumeration failed due to an IDA backend error.

    Example success payload:
        {
            "functions": [
                {
                    "address": 4198400,
                    "name": "_main",
                    "size": 152,
                    "signature": "int __cdecl main(int argc, const char **argv)",
                    "flags": {"noreturn": False, "library": False, "thunk": False},
                    "comment": "",
                    "repeatable_comment": "",
                },
            ],
        }"""
    raise NotImplementedError


def get_function_by_name(name: str) -> GetFunctionByNameResult:
    """Function descriptor resolved by exact symbol name.

    Use this when you have a name from `get_names` or external context and need
    its address and size. Accepts both mangled and demangled names.
    See also `get_functions`, `get_function_at`, and `demangle_name`.

    Args:
        name: Function name (mangled or demangled) to look up.

    Returns:
        Success payload `{address: int, name: str, size: int, signature: str,
        flags: {noreturn: bool, library: bool, thunk: bool}, comment: str,
        repeatable_comment: str}` or `{"error": str}`.

    Errors:
        - No function exists with the given name.
        - Function lookup failed due to an IDA backend error.

    Example success payload:
        {
            "address": 4198400,
            "name": "_main",
            "size": 152,
            "signature": "int __cdecl main(int argc, const char **argv)",
            "flags": {"noreturn": False, "library": False, "thunk": False},
            "comment": "",
            "repeatable_comment": "",
        }"""
    raise NotImplementedError


def get_function_at(address: int) -> GetFunctionAtResult:
    """Function descriptor for a function start address.

    Use this when you already have a known function start EA and need canonical
    metadata. See also `get_functions`, `get_function_by_name`, and
    `get_function_disassembly_at`.

    Args:
        address: Effective address that must be exactly a function start.

    Returns:
        Success payload `{address: int, name: str, size: int, signature: str,
        flags: {noreturn: bool, library: bool, thunk: bool}, comment: str,
        repeatable_comment: str}` or `{"error": str}`.

    Errors:
        - Address does not resolve to any function.
        - Address resolves inside a function but is not the function start.
        - Function lookup failed due to an IDA backend error.

    Example success payload:
        {
            "address": 4198400,
            "name": "_main",
            "size": 152,
            "signature": "int __cdecl main(int argc, const char **argv)",
            "flags": {"noreturn": False, "library": False, "thunk": False},
            "comment": "",
            "repeatable_comment": "",
        }"""
    raise NotImplementedError


def get_function_disassembly_at(address: int) -> GetFunctionDisassemblyAtResult:
    """Linear-disassembly lines for the containing function.

    Use this for text-based inspection of a full function body, including comments
    and labels as rendered by IDA. See also `get_instruction_at`,
    `get_disassembly_at`, and `decompile_function_at`.

    Args:
        address: Effective address anywhere inside the target function.

    Returns:
        Success payload `{disassembly: list[str]}` or `{"error": str}`.

    Errors:
        - Address does not resolve to a function.
        - Disassembly generation failed.

    Example success payload:
        {
            "disassembly": [
                "push ebp",
                "mov ebp, esp",
                "call sub_401200",
            ],
        }"""
    raise NotImplementedError


def decompile_function_at(address: int) -> DecompileFunctionAtResult:
    """Hex-Rays pseudocode lines for the containing function.

    Use this when higher-level C-like structure is needed for reasoning, triage,
    or summarization. See also `get_function_at`, `get_function_disassembly_at`,
    and `get_basic_blocks_at`.

    Args:
        address: Effective address anywhere inside the target function.

    Returns:
        Success payload `{pseudocode: list[str]}` or `{"error": str}`.

    Errors:
        - Address does not resolve to a function.
        - Decompilation failed (for example, no decompiler available).

    Example success payload:
        {
            "pseudocode": [
                "int __cdecl main(int argc, const char **argv)",
                "{",
                "  return sub_401200(argc, argv);",
                "}",
            ],
        }"""
    raise NotImplementedError


def get_callers_at(address: int) -> GetCallersAtResult:
    """Functions that call the containing function.

    Use this for inbound call-graph analysis, impact assessment, and reachability
    queries. See also `get_callees_at`, `get_xrefs_to_at`, and `get_function_at`.

    Args:
        address: Effective address anywhere inside the target function.

    Returns:
        Success payload `{callers: list[{address: int, name: str}]}` or
        `{"error": str}`.

    Errors:
        - Address does not resolve to a function.
        - Caller analysis failed.

    Example success payload:
        {
            "callers": [
                {"address": 4199000, "name": "sub_4013A8"},
                {"address": 4200100, "name": "start"},
            ],
        }"""
    raise NotImplementedError


def get_callees_at(address: int) -> GetCalleesAtResult:
    """Functions called by the containing function.

    Use this for outbound call-graph traversal and dependency discovery. See also
    `get_callers_at`, `get_xrefs_from_at`, and `get_function_at`.

    Args:
        address: Effective address anywhere inside the target function.

    Returns:
        Success payload `{callees: list[{address: int, name: str}]}` or
        `{"error": str}`.

    Errors:
        - Address does not resolve to a function.
        - Callee analysis failed.

    Example success payload:
        {
            "callees": [
                {"address": 4198608, "name": "_printf"},
                {"address": 4198700, "name": "sub_40124C"},
            ],
        }"""
    raise NotImplementedError


def get_basic_blocks_at(address: int) -> GetBasicBlocksAtResult:
    """Control-flow graph basic blocks for the containing function.

    Use this to build custom CFG analyses, detect branch structure, or map
    execution regions. See also `get_function_disassembly_at`, `get_callers_at`,
    and `get_callees_at`.

    Args:
        address: Effective address anywhere inside the target function.

    Returns:
        Success payload
        `{basic_blocks: list[{start: int, end: int, successors: list[int],
        predecessors: list[int]}]}` or `{"error": str}`.

    Errors:
        - Address does not resolve to a function.
        - CFG construction or serialization failed.

    Example success payload:
        {
            "basic_blocks": [
                {
                    "start": 4198400,
                    "end": 4198412,
                    "successors": [4198420],
                    "predecessors": [],
                },
                {
                    "start": 4198420,
                    "end": 4198450,
                    "successors": [],
                    "predecessors": [4198400],
                },
            ],
        }"""
    raise NotImplementedError


def get_xrefs_to_at(address: int) -> GetXrefsToAtResult:
    """Cross-references that target an address.

    Use this for incoming reference analysis at instruction, data, or function
    granularity. See also `get_xrefs_from_at`, `get_callers_at`, and
    `get_address_type`.

    Args:
        address: Effective address that is the xref target.

    Returns:
        Success payload
        `{xrefs: list[{from_address: int, type: str, is_call: bool,
        is_jump: bool}]}` or `{"error": str}`.

    Errors:
        - Xref enumeration failed.

    Example success payload:
        {
            "xrefs": [
                {
                    "from_address": 4199100,
                    "type": "fl_CN",
                    "is_call": True,
                    "is_jump": False,
                }
            ],
        }"""
    raise NotImplementedError


def get_xrefs_from_at(address: int) -> GetXrefsFromAtResult:
    """Cross-references that originate at an address.

    Use this to inspect where a specific instruction or data item points to. See
    also `get_xrefs_to_at`, `get_callees_at`, and `get_disassembly_at`.

    Args:
        address: Effective address that is the xref source.

    Returns:
        Success payload
        `{xrefs: list[{to_address: int, type: str, is_call: bool,
        is_jump: bool}]}` or `{"error": str}`.

    Errors:
        - Xref enumeration failed.

    Example success payload:
        {
            "xrefs": [
                {
                    "to_address": 4198608,
                    "type": "fl_CN",
                    "is_call": True,
                    "is_jump": False,
                }
            ],
        }"""
    raise NotImplementedError


def get_strings() -> GetStringsResult:
    """All strings recognized by IDA analysis.

    Use this for credential hunts, IOC extraction, and UI/text discovery. See also
    `get_string_at`, `find_bytes`, and `get_segments`.

    Args:
        None.

    Returns:
        Success payload
        `{strings: list[{address: int, length: int, type: str, value: str}]}` or
        `{"error": str}`.

    Errors:
        - String enumeration failed.

    Example success payload:
        {
            "strings": [
                {"address": 4220000, "length": 12, "type": "C", "value": "Hello world"}
            ],
        }"""
    raise NotImplementedError


def get_string_at(address: int) -> GetStringAtResult:
    """Null-terminated C string decoded at an address.

    Use this for point lookups when an address is known from xrefs or data-flow
    analysis. See also `get_strings`, `get_bytes_at`, and `get_address_type`.

    Args:
        address: Effective address where the string is expected to start.

    Returns:
        Success payload `{string: str}` or `{"error": str}`.

    Errors:
        - Address does not contain a decodable C string.
        - String read failed due to an IDA backend error.

    Example success payload:
        {"string": "kernel32.dll"}"""
    raise NotImplementedError


def get_segments() -> GetSegmentsResult:
    """Memory-segment descriptors for the loaded database.

    Use this to understand memory layout, permissions, and section boundaries
    before range-based analysis. See also `get_binary_info`, `get_bytes_at`, and
    `get_address_type`.

    Args:
        None.

    Returns:
        Success payload
        `{segments: list[{name: str, start: int, end: int, size: int,
        permissions: int, class: str, bitness: int}]}` or `{"error": str}`.

    Errors:
        - Segment enumeration failed.

    Example success payload:
        {
            "segments": [
                {
                    "name": ".text",
                    "start": 4198400,
                    "end": 4214784,
                    "size": 16384,
                    "permissions": 5,
                    "class": "CODE",
                    "bitness": 1,
                }
            ],
        }"""
    raise NotImplementedError


def get_names() -> GetNamesResult:
    """All named addresses known to IDA.

    Use this to build symbol maps or fuzzy-name search indexes. Names are
    demangled when applicable. See also `get_name_at`, `get_functions`, and
    `demangle_name`.

    Args:
        None.

    Returns:
        Success payload `{names: list[{address: int, name: str}]}` or
        `{"error": str}`.

    Errors:
        - Name enumeration failed.

    Example success payload:
        {
            "names": [
                {"address": 4198400, "name": "_main"},
                {"address": 4198608, "name": "_printf"},
            ],
        }"""
    raise NotImplementedError


def get_name_at(address: int) -> GetNameAtResult:
    """Symbol name at an exact address.

    Use this for point queries when you already have an address from xrefs, bytes,
    or instruction traversal. See also `get_names`, `get_function_at`, and
    `demangle_name`.

    Args:
        address: Effective address to resolve to a symbol name.

    Returns:
        Success payload `{name: str}` or `{"error": str}`.

    Errors:
        - Address has no symbol name.
        - Name lookup failed.

    Example success payload:
        {"name": "_main"}"""
    raise NotImplementedError


def demangle_name(name: str) -> DemangleNameResult:
    """Demangled form of a mangled symbol string.

    Use this to normalize compiler-generated names for reporting or matching. See
    also `get_name_at`, `get_names`, and `get_function_by_name`.

    Args:
        name: Raw symbol name (mangled or plain).

    Returns:
        Success payload `{demangled_name: str}` or `{"error": str}`.

    Errors:
        - Name demangling failed due to an IDA backend error.

    Example success payload:
        {"demangled_name": "std::basic_string<char,...>::basic_string()"}"""
    raise NotImplementedError


def get_imports() -> GetImportsResult:
    """Imported symbols referenced by the binary.

    Use this to understand external dependencies and API usage. This function uses
    `db.imports` when available and falls back to `ida_nalt` enumeration. See also
    `get_entries`, `get_names`, and `find_bytes`.

    Args:
        None.

    Returns:
        Success payload
        `{imports: list[{address: int, name: str, module: str, ordinal: int}]}` or
        `{"error": str}`.

    Errors:
        - Import enumeration failed in both primary and fallback providers.

    Example success payload:
        {
            "imports": [
                {
                    "address": 4211000,
                    "name": "CreateFileA",
                    "module": "KERNEL32.dll",
                    "ordinal": 0,
                }
            ],
        }"""
    raise NotImplementedError


def get_entries() -> GetEntriesResult:
    """Entry points and exported entry records.

    Use this to identify initial execution entry points and exported APIs in the
    loaded module. See also `get_binary_info`, `get_functions`, and `get_imports`.

    Args:
        None.

    Returns:
        Success payload
        `{entries: list[{ordinal: int, address: int, name: str,
        forwarder: str | None}]}` or `{"error": str}`.

    Errors:
        - Entry enumeration failed.

    Example success payload:
        {
            "entries": [
                {
                    "ordinal": 1,
                    "address": 4198400,
                    "name": "start",
                    "forwarder": None,
                }
            ],
        }"""
    raise NotImplementedError


def get_bytes_at(address: int, size: int) -> GetBytesAtResult:
    """Raw byte values from a contiguous address range.

    Use this for opcode extraction, signature generation, and binary patch
    preparation. See also `find_bytes`, `get_instruction_at`, and
    `get_address_type`.

    Args:
        address: Effective address where reading should start.
        size: Number of bytes to read. Must be non-negative.

    Returns:
        Success payload `{bytes: list[int]}` where each element is in `0..255`, or
        `{"error": str}`.

    Errors:
        - `size` is negative.
        - Address range is invalid or unreadable.

    Example success payload:
        {"bytes": [85, 139, 236, 131, 236, 16]}"""
    raise NotImplementedError


def find_bytes(pattern: list[int]) -> FindBytesResult:
    """Addresses where an exact byte pattern occurs.

    Use this for signature scans, constant lookup, or locating known instruction
    prologues. See also `get_bytes_at`, `get_strings`, and `get_xrefs_to_at`.

    Args:
        pattern: Non-empty list of integers in the range `0..255`.

    Returns:
        Success payload `{addresses: list[int]}` or `{"error": str}`.

    Errors:
        - Pattern is empty.
        - Pattern contains a non-integer element.
        - Pattern contains an out-of-range byte value.
        - Search operation failed.

    Example success payload:
        {"addresses": [4198400, 4201804]}"""
    raise NotImplementedError


def get_disassembly_at(address: int) -> GetDisassemblyAtResult:
    """Disassembly text for one instruction address.

    Use this for compact instruction rendering without fetching the full structured
    instruction object. See also `get_instruction_at`,
    `get_function_disassembly_at`, and `get_bytes_at`.

    Args:
        address: Effective address expected to decode as an instruction.

    Returns:
        Success payload `{disassembly: str}` or `{"error": str}`.

    Errors:
        - Address does not decode to an instruction.
        - Disassembly retrieval failed.

    Example success payload:
        {"disassembly": "call sub_401200"}"""
    raise NotImplementedError


def get_instruction_at(address: int) -> GetInstructionAtResult:
    """Structured instruction fields for one address.

    Use this when downstream tooling needs machine-readable mnemonic, size, and
    call classification. See also `get_disassembly_at`, `get_bytes_at`, and
    `get_function_disassembly_at`.

    Args:
        address: Effective address expected to decode as an instruction.

    Returns:
        Success payload
        `{address: int, size: int, mnemonic: str, disassembly: str, is_call: bool}`
        or `{"error": str}`.

    Errors:
        - Address does not decode to an instruction.
        - Instruction retrieval or serialization failed.

    Example success payload:
        {
            "address": 4198400,
            "size": 5,
            "mnemonic": "call",
            "disassembly": "call sub_401200",
            "is_call": True,
        }"""
    raise NotImplementedError


def get_address_type(address: int) -> GetAddressTypeResult:
    """Address classification as code, data, unknown, or invalid.

    Use this before decoding bytes or interpreting symbols at arbitrary locations.
    See also `get_bytes_at`, `get_instruction_at`, and `get_disassembly_at`.

    Args:
        address: Effective address to classify.

    Returns:
        Success payload
        `{address_type: Literal["code", "data", "unknown", "invalid"]}` or
        `{"error": str}`.

    Errors:
        - Address validation failed due to an IDA backend error.

    Example success payload:
        {"address_type": "code"}"""
    raise NotImplementedError


def get_comment_at(address: int) -> GetCommentAtResult:
    """Comment text attached to an exact address.

    Use this to collect analyst annotations and inline notes for reporting or
    agent context. See also `get_disassembly_at`, `get_name_at`, and
    `get_instruction_at`.

    Args:
        address: Effective address whose comment should be retrieved.

    Returns:
        Success payload `{comment: str}` or `{"error": str}`.

    Errors:
        - Address has no comment.
        - Comment lookup failed.

    Example success payload:
        {"comment": "decrypts config blob"}"""
    raise NotImplementedError
