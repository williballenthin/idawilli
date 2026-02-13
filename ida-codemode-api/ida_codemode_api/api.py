"""IDA Codemode API.

Portable analysis APIs for IDA Pro suitable for sandboxed code execution,
JSON-RPC exposure, and LLM tool use.

All APIs use JSON-safe primitives (dicts, lists, ints, strings, bools,
None). Use :func:`create_api_from_database` to build concrete callables
bound to an open ``ida_domain.Database``.
"""

from __future__ import annotations

import ast
import re
from typing import Any, Callable, Literal, TypedDict


class BinaryInfo(TypedDict):
    path: str
    module: str
    architecture: str
    bitness: int
    format: str
    base_address: int
    entry_point: int
    minimum_ea: int
    maximum_ea: int
    filesize: int
    md5: str
    sha256: str
    crc32: int


class FunctionInfo(TypedDict):
    address: int
    name: str
    size: int


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


TYPE_STUBS = '''\
from typing import Literal, TypedDict


class BinaryInfo(TypedDict):
    path: str
    module: str
    architecture: str
    bitness: int
    format: str
    base_address: int
    entry_point: int
    minimum_ea: int
    maximum_ea: int
    filesize: int
    md5: str
    sha256: str
    crc32: int


class FunctionInfo(TypedDict):
    address: int
    name: str
    size: int


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


def get_binary_info() -> BinaryInfo:
    """Return global metadata about the analyzed binary."""
    ...


def get_functions() -> list[FunctionInfo]:
    """Return every discovered function descriptor."""
    ...


def get_function_by_name(name: str) -> FunctionInfo | None:
    """Look up a function by exact symbolic name."""
    ...


def get_function_at(address: int) -> FunctionInfo | None:
    """Look up the function that starts at the given address."""
    ...


def get_function_disassembly_at(address: int) -> list[str]:
    """Return disassembly lines for the function at address."""
    ...


def decompile_function_at(address: int) -> list[str]:
    """Return Hex-Rays pseudocode lines for the function at address."""
    ...


def get_function_signature_at(address: int) -> str | None:
    """Return the C-like function signature at address."""
    ...


def get_callers_at(address: int) -> list[NamedAddress]:
    """Return callers of the function at address."""
    ...


def get_callees_at(address: int) -> list[NamedAddress]:
    """Return callees of the function at address."""
    ...


def get_basic_blocks_at(address: int) -> list[BasicBlockInfo]:
    """Return CFG basic blocks for the function at address."""
    ...


def get_xrefs_to_at(address: int) -> list[XrefToInfo]:
    """Return all cross-references that target address."""
    ...


def get_xrefs_from_at(address: int) -> list[XrefFromInfo]:
    """Return all cross-references that originate at address."""
    ...


def get_strings() -> list[StringInfo]:
    """Return every string recognized by IDA."""
    ...


def get_string_at(address: int) -> str | None:
    """Return a null-terminated C string at address."""
    ...


def get_segments() -> list[SegmentInfo]:
    """Return all memory segment descriptors."""
    ...


def get_names() -> list[NamedAddress]:
    """Return all named addresses."""
    ...


def get_name_at(address: int) -> str | None:
    """Return the symbol name at address."""
    ...


def demangle_name(name: str) -> str:
    """Demangle a C++ symbol name."""
    ...


def get_imports() -> list[ImportInfo]:
    """Return imported symbols."""
    ...


def get_entries() -> list[EntryPointInfo]:
    """Return entry points and exported symbols."""
    ...


def get_bytes_at(address: int, size: int) -> list[int]:
    """Return raw bytes at address."""
    ...


def find_bytes(pattern: list[int]) -> list[int]:
    """Return addresses matching a byte pattern."""
    ...


def get_disassembly_at(address: int) -> str | None:
    """Return disassembly text for one instruction."""
    ...


def get_instruction_at(address: int) -> InstructionInfo | None:
    """Return structured instruction data at address."""
    ...


def get_address_type(address: int) -> AddressType:
    """Classify address as code, data, unknown, or invalid."""
    ...


def get_comment_at(address: int) -> str | None:
    """Return the comment attached to address."""
    ...
'''


FUNCTION_NAMES: list[str] = [
    "get_binary_info",
    "get_functions",
    "get_function_by_name",
    "get_function_at",
    "get_function_disassembly_at",
    "decompile_function_at",
    "get_function_signature_at",
    "get_callers_at",
    "get_callees_at",
    "get_basic_blocks_at",
    "get_xrefs_to_at",
    "get_xrefs_from_at",
    "get_strings",
    "get_string_at",
    "get_segments",
    "get_names",
    "get_name_at",
    "demangle_name",
    "get_imports",
    "get_entries",
    "get_bytes_at",
    "find_bytes",
    "get_disassembly_at",
    "get_instruction_at",
    "get_address_type",
    "get_comment_at",
]


_TYPED_DICTS: dict[str, Any] = {
    "BinaryInfo": BinaryInfo,
    "FunctionInfo": FunctionInfo,
    "NamedAddress": NamedAddress,
    "BasicBlockInfo": BasicBlockInfo,
    "XrefToInfo": XrefToInfo,
    "XrefFromInfo": XrefFromInfo,
    "StringInfo": StringInfo,
    "SegmentInfo": SegmentInfo,
    "ImportInfo": ImportInfo,
    "EntryPointInfo": EntryPointInfo,
    "InstructionInfo": InstructionInfo,
}


def _typed_dict_shape(name: str) -> str:
    cls = _TYPED_DICTS[name]
    keys = ", ".join(cls.__annotations__.keys())
    return "{" + keys + "}"


def _render_return_annotation(annotation: str) -> str:
    rendered = annotation
    for name in sorted(_TYPED_DICTS.keys(), key=len, reverse=True):
        rendered = re.sub(rf"\b{name}\b", _typed_dict_shape(name), rendered)
    return rendered


def _api_rows_from_type_stubs() -> list[tuple[str, str, str, str]]:
    module = ast.parse(TYPE_STUBS)
    rows: dict[str, tuple[str, str, str, str]] = {}

    for node in module.body:
        if not isinstance(node, ast.FunctionDef):
            continue

        arg_names = [arg.arg for arg in node.args.args]
        signature = f"{node.name}({', '.join(arg_names)})"
        returns = ast.unparse(node.returns) if node.returns is not None else "Any"

        doc = ast.get_docstring(node) or ""
        description = doc.strip().splitlines()[0] if doc.strip() else ""

        rows[node.name] = (node.name, signature, returns, description)

    return [rows[name] for name in FUNCTION_NAMES if name in rows]


def create_api_from_database(db: Any) -> dict[str, Callable[..., Any]]:
    """Build API callables backed by an open ``ida_domain.Database``.

    Args:
        db: Open database object from ``ida_domain``.

    Returns:
        Mapping from API name to callable implementation.

    Example:
        Build the API and inspect function docstrings.

    Example::

        from ida_domain import Database
        from ida_codemode_api import create_api_from_database

        with Database.open(path, options) as db:
            api = create_api_from_database(db)
            print(api["get_binary_info"]()["module"])
            print(api["get_binary_info"].__doc__.splitlines()[0])
    """

    def _serialize_function(func: Any) -> FunctionInfo:
        return {
            "address": int(func.start_ea),
            "name": str(db.functions.get_name(func)),
            "size": int(func.size() if callable(func.size) else func.size),
        }

    def get_binary_info() -> BinaryInfo:
        """Return global metadata about the analyzed binary.

        Example result::

            {
                "path": "/tmp/sample.exe",
                "module": "sample.exe",
                "architecture": "metapc",
                "bitness": 32,
                "format": "PE",
                "base_address": 4194304,
                "entry_point": 4198400,
                "minimum_ea": 4194304,
                "maximum_ea": 4259840,
                "filesize": 123456,
                "md5": "...",
                "sha256": "...",
                "crc32": 123456789,
            }
        """
        return {
            "path": str(db.path),
            "module": str(db.module),
            "architecture": str(db.architecture),
            "bitness": int(db.bitness),
            "format": str(db.format),
            "base_address": int(db.base_address),
            "entry_point": int(db.start_ip),
            "minimum_ea": int(db.minimum_ea),
            "maximum_ea": int(db.maximum_ea),
            "filesize": int(db.filesize),
            "md5": str(db.md5),
            "sha256": str(db.sha256),
            "crc32": int(db.crc32),
        }

    def get_functions() -> list[FunctionInfo]:
        """Return every discovered function descriptor.

        See also: ``get_function_at``, ``get_function_by_name``,
        ``get_function_signature_at``, ``get_function_disassembly_at``,
        ``get_callers_at``, ``get_callees_at``, ``get_basic_blocks_at``.

        Example result::

            [{"address": 4198400, "name": "main", "size": 1337}]
        """
        return [_serialize_function(func) for func in db.functions]

    def get_function_by_name(name: str) -> FunctionInfo | None:
        """Look up a function by exact symbolic name.

        Example result::

            {"address": 4198400, "name": "main", "size": 1337}
        """
        func = db.functions.get_function_by_name(name)
        if func is None:
            return None
        return _serialize_function(func)

    def get_function_at(address: int) -> FunctionInfo | None:
        """Look up the function that starts at the given address.

        Example result::

            {"address": 4198400, "name": "main", "size": 1337}
        """
        try:
            func = db.functions.get_at(address)
        except Exception:
            return None
        if func is None:
            return None
        if int(func.start_ea) != int(address):
            return None
        return _serialize_function(func)

    def get_function_disassembly_at(address: int) -> list[str]:
        """Return disassembly lines for the function at address.

        Example result::

            ["push ebp", "mov ebp, esp", "..."]
        """
        try:
            func = db.functions.get_at(address)
        except Exception:
            return []
        if func is None:
            return []
        return list(db.functions.get_disassembly(func))

    def decompile_function_at(address: int) -> list[str]:
        """Return Hex-Rays pseudocode lines for the function at address.

        Example result::

            ["int __cdecl main(int argc, const char **argv)", "{", "  return 0;", "}"]
        """
        try:
            func = db.functions.get_at(address)
        except Exception:
            return []
        if func is None:
            return []
        try:
            result = db.functions.get_pseudocode(func)
            return list(result) if result else []
        except Exception:
            return []

    def get_function_signature_at(address: int) -> str | None:
        """Return the C-like function signature at address.

        Example result::

            "int __cdecl main(int argc, const char **argv)"
        """
        try:
            func = db.functions.get_at(address)
        except Exception:
            return None
        if func is None:
            return None
        sig = db.functions.get_signature(func)
        return str(sig) if sig is not None else None

    def get_callers_at(address: int) -> list[NamedAddress]:
        """Return callers of the function at address.

        Example result::

            [{"address": 4202496, "name": "sub_402000"}]
        """
        try:
            func = db.functions.get_at(address)
        except Exception:
            return []
        if func is None:
            return []
        return [
            {
                "address": int(caller.start_ea),
                "name": str(db.functions.get_name(caller)),
            }
            for caller in db.functions.get_callers(func)
        ]

    def get_callees_at(address: int) -> list[NamedAddress]:
        """Return callees of the function at address.

        Example result::

            [{"address": 4206592, "name": "CreateFileA"}]
        """
        try:
            func = db.functions.get_at(address)
        except Exception:
            return []
        if func is None:
            return []
        return [
            {
                "address": int(callee.start_ea),
                "name": str(db.functions.get_name(callee)),
            }
            for callee in db.functions.get_callees(func)
        ]

    def get_basic_blocks_at(address: int) -> list[BasicBlockInfo]:
        """Return CFG basic blocks for the function at address.

        Example result::

            [{"start": 4198400, "end": 4198410, "successors": [4198420], "predecessors": []}]
        """
        try:
            func = db.functions.get_at(address)
        except Exception:
            return []
        if func is None:
            return []
        flowchart = db.functions.get_flowchart(func)
        if flowchart is None:
            return []

        results: list[BasicBlockInfo] = []
        for block in flowchart:
            results.append({
                "start": int(block.start_ea),
                "end": int(block.end_ea),
                "successors": [int(s.start_ea) for s in block.succs()],
                "predecessors": [int(p.start_ea) for p in block.preds()],
            })
        return results

    def get_xrefs_to_at(address: int) -> list[XrefToInfo]:
        """Return all cross-references that target address.

        Example result::

            [{"from_address": 4202496, "type": "CALL_NEAR", "is_call": True, "is_jump": False}]
        """
        results: list[XrefToInfo] = []
        try:
            for xref in db.xrefs.to_ea(address):
                results.append({
                    "from_address": int(xref.from_ea),
                    "type": str(xref.type.name),
                    "is_call": bool(xref.is_call),
                    "is_jump": bool(xref.is_jump),
                })
        except Exception:
            pass
        return results

    def get_xrefs_from_at(address: int) -> list[XrefFromInfo]:
        """Return all cross-references that originate at address.

        Example result::

            [{"to_address": 4206592, "type": "CALL_NEAR", "is_call": True, "is_jump": False}]
        """
        results: list[XrefFromInfo] = []
        try:
            for xref in db.xrefs.from_ea(address):
                results.append({
                    "to_address": int(xref.to_ea),
                    "type": str(xref.type.name),
                    "is_call": bool(xref.is_call),
                    "is_jump": bool(xref.is_jump),
                })
        except Exception:
            pass
        return results

    def get_strings() -> list[StringInfo]:
        """Return every string recognized by IDA.

        Example result::

            [{"address": 4214784, "length": 12, "type": "C", "value": "Hello world"}]
        """
        results: list[StringInfo] = []
        for s in db.strings:
            value = s.contents
            if isinstance(value, (bytes, bytearray)):
                value = value.decode("utf-8", errors="replace")
            results.append({
                "address": int(s.address),
                "length": int(s.length),
                "type": str(s.type.name) if hasattr(s.type, "name") else str(s.type),
                "value": str(value),
            })
        return results

    def get_string_at(address: int) -> str | None:
        """Return a null-terminated C string at address.

        Example result::

            "kernel32.dll"
        """
        try:
            result = db.bytes.get_cstring_at(address)
            return str(result) if result is not None else None
        except Exception:
            return None

    def get_segments() -> list[SegmentInfo]:
        """Return all memory segment descriptors.

        Example result::

            [{"name": ".text", "start": 4194304, "end": 4202496, "size": 8192, "permissions": 5, "class": "CODE", "bitness": 32}]
        """
        results: list[SegmentInfo] = []
        for seg in db.segments:
            results.append({
                "name": str(db.segments.get_name(seg)),
                "start": int(seg.start_ea),
                "end": int(seg.end_ea),
                "size": int(db.segments.get_size(seg)),
                "permissions": int(seg.perm),
                "class": str(db.segments.get_class(seg)),
                "bitness": int(db.segments.get_bitness(seg)),
            })
        return results

    def get_names() -> list[NamedAddress]:
        """Return all named addresses.

        Example result::

            [{"address": 4198400, "name": "main"}]
        """
        return [{"address": int(ea), "name": str(name)} for ea, name in db.names]

    def get_name_at(address: int) -> str | None:
        """Return the symbol name at address.

        Example result::

            "main"
        """
        try:
            result = db.names.get_at(address)
        except Exception:
            return None
        return str(result) if result else None

    def demangle_name(name: str) -> str:
        """Demangle a C++ symbol name.

        Example result::

            "std::basic_string<char>::size() const"
        """
        result = db.names.demangle_name(name)
        return str(result) if result else str(name)

    def get_imports() -> list[ImportInfo]:
        """Return imported symbols.

        Example result::

            [{"address": 4206592, "name": "CreateFileA", "module": "KERNEL32", "ordinal": 0}]
        """
        results: list[ImportInfo] = []

        # Preferred path: ida_domain may expose db.imports.
        if hasattr(db, "imports"):
            try:
                for imp in db.imports.get_all_imports():
                    results.append({
                        "address": int(imp.address),
                        "name": str(imp.name),
                        "module": str(imp.module_name),
                        "ordinal": int(imp.ordinal),
                    })
                return results
            except Exception:
                results = []

        # Fallback path: use IDA's import-enumeration APIs directly.
        try:
            import ida_nalt  # type: ignore
        except Exception:
            return results

        try:
            module_count = int(ida_nalt.get_import_module_qty())
        except Exception:
            return results

        for module_index in range(module_count):
            module_name = ida_nalt.get_import_module_name(module_index)
            module_name_str = str(module_name) if module_name else ""

            def _collect(ea: int, name: str | None, ordinal: int, _m: str = module_name_str) -> bool:
                results.append({
                    "address": int(ea),
                    "name": str(name) if name is not None else "",
                    "module": _m,
                    "ordinal": int(ordinal),
                })
                return True

            try:
                ida_nalt.enum_import_names(module_index, _collect)
            except Exception:
                continue

        return results

    def get_entries() -> list[EntryPointInfo]:
        """Return entry points and exported symbols.

        Example result::

            [{"ordinal": 1, "address": 4198400, "name": "_DllMain@12", "forwarder": None}]
        """
        results: list[EntryPointInfo] = []
        for entry in db.entries:
            forwarder: str | None = None
            has_forwarder = getattr(entry, "has_forwarder", None)
            if callable(has_forwarder):
                if bool(has_forwarder()):
                    forwarder = str(entry.forwarder_name)
            elif bool(has_forwarder):
                forwarder = str(entry.forwarder_name)
            results.append({
                "ordinal": int(entry.ordinal),
                "address": int(entry.address),
                "name": str(entry.name),
                "forwarder": forwarder,
            })
        return results

    def get_bytes_at(address: int, size: int) -> list[int]:
        """Return raw bytes at address.

        Example result::

            [85, 139, 236, 131, 236, 8]
        """
        try:
            data = db.bytes.get_bytes_at(address, size)
        except Exception:
            return []
        if data is None:
            return []
        return list(data)

    def find_bytes(pattern: list[int]) -> list[int]:
        """Return addresses matching a byte pattern.

        Example result::

            [4198400, 4202496]
        """
        return [int(ea) for ea in db.bytes.find_binary_sequence(bytes(pattern))]

    def get_disassembly_at(address: int) -> str | None:
        """Return disassembly text for one instruction.

        Example result::

            "push    ebp"
        """
        try:
            result = db.bytes.get_disassembly_at(address)
            return str(result) if result is not None else None
        except Exception:
            return None

    def get_instruction_at(address: int) -> InstructionInfo | None:
        """Return structured instruction data at address.

        Example result::

            {"address": 4198400, "size": 1, "mnemonic": "push", "disassembly": "push ebp", "is_call": False}
        """
        try:
            insn = db.instructions.get_at(address)
        except Exception:
            return None
        if insn is None:
            return None
        return {
            "address": int(insn.ea),
            "size": int(insn.size),
            "mnemonic": str(db.instructions.get_mnemonic(insn)),
            "disassembly": str(db.instructions.get_disassembly(insn)),
            "is_call": bool(db.instructions.is_call_instruction(insn)),
        }

    def get_address_type(address: int) -> AddressType:
        """Classify address as code, data, unknown, or invalid.

        Example result::

            "code"
        """
        if not bool(db.is_valid_ea(address)):
            return "invalid"

        try:
            if bool(db.bytes.is_code_at(address)):
                return "code"
        except Exception:
            pass

        try:
            if bool(db.bytes.is_data_at(address)):
                return "data"
        except Exception:
            pass

        try:
            if bool(db.bytes.is_unknown_at(address)):
                return "unknown"
        except Exception:
            pass

        return "unknown"

    def get_comment_at(address: int) -> str | None:
        """Return the comment attached to address.

        Example result::

            "decrypts config"
        """
        try:
            result = db.comments.get_at(address)
        except Exception:
            return None
        return str(result) if result else None

    api: dict[str, Callable[..., Any]] = {
        "get_binary_info": get_binary_info,
        "get_functions": get_functions,
        "get_function_by_name": get_function_by_name,
        "get_function_at": get_function_at,
        "get_function_disassembly_at": get_function_disassembly_at,
        "decompile_function_at": decompile_function_at,
        "get_function_signature_at": get_function_signature_at,
        "get_callers_at": get_callers_at,
        "get_callees_at": get_callees_at,
        "get_basic_blocks_at": get_basic_blocks_at,
        "get_xrefs_to_at": get_xrefs_to_at,
        "get_xrefs_from_at": get_xrefs_from_at,
        "get_strings": get_strings,
        "get_string_at": get_string_at,
        "get_segments": get_segments,
        "get_names": get_names,
        "get_name_at": get_name_at,
        "demangle_name": demangle_name,
        "get_imports": get_imports,
        "get_entries": get_entries,
        "get_bytes_at": get_bytes_at,
        "find_bytes": find_bytes,
        "get_disassembly_at": get_disassembly_at,
        "get_instruction_at": get_instruction_at,
        "get_address_type": get_address_type,
        "get_comment_at": get_comment_at,
    }

    return api


def api_reference() -> str:
    """Return a Markdown function table generated from stubs/docstrings."""
    rows = _api_rows_from_type_stubs()

    lines = [
        "## Function reference",
        "",
        "| Function | Returns | Description |",
        "|----------|---------|-------------|",
    ]

    for _, signature, returns, description in rows:
        rendered_return = _render_return_annotation(returns)
        lines.append(f"| `{signature}` | `{rendered_return}` | {description} |")

    return "\n".join(lines)
