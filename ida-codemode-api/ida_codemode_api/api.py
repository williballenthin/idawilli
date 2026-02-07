"""IDA Codemode API: the 28-function analysis contract for IDA Pro.

Defines a portable API of pure-function analysis routines that serialize
IDA domain objects into plain Python primitives (dicts, lists, ints,
strings).  Every function takes JSON-safe arguments and returns JSON-safe
values, making the API suitable for in-process sandboxes, JSON-RPC
servers, or any other execution backend.

Use :func:`build_ida_functions` to create a concrete implementation
backed by an ``ida_domain.Database``.

Exposed functions
-----------------

Database metadata
    ``get_binary_info``

Function enumeration & lookup
    ``enumerate_functions``, ``get_function_by_name``

Function analysis
    ``disassemble_function``, ``decompile_function``,
    ``get_function_signature``, ``get_callers``,
    ``get_callees``, ``get_basic_blocks``

Cross-references
    ``get_xrefs_to``, ``get_xrefs_from``

Strings
    ``enumerate_strings``, ``get_string_at``

Segments
    ``enumerate_segments``

Names / symbols
    ``enumerate_names``, ``get_name_at``, ``demangle_name``

Imports & entry points
    ``enumerate_imports``, ``enumerate_entries``

Bytes / memory
    ``read_bytes``, ``find_bytes``, ``get_disassembly_at``,
    ``get_instruction_at``

Address classification
    ``is_code_at``, ``is_data_at``, ``is_valid_address``

Comments
    ``get_comment_at``

Utilities
    ``random_int``
"""

from __future__ import annotations

import random as _random
from pathlib import Path
from typing import Any, Callable

_PROMPTS_DIR = Path(__file__).parent / "prompts"


# ---------------------------------------------------------------------------
# Type-checking stubs for every API function
# ---------------------------------------------------------------------------

TYPE_STUBS = """\
from typing import Any

# --- Database metadata ---

def get_binary_info() -> dict[str, Any]:
    \"\"\"Return metadata about the binary under analysis.\"\"\"
    ...

# --- Function enumeration & lookup ---

def enumerate_functions() -> list[dict[str, Any]]:
    \"\"\"Return all functions: [{address, name, size}, ...].\"\"\"
    ...

def get_function_by_name(name: str) -> dict[str, Any] | None:
    \"\"\"Look up a function by *name*, returning its descriptor or None.\"\"\"
    ...

# --- Function analysis ---

def disassemble_function(address: int) -> list[str]:
    \"\"\"Return disassembly lines for the function at *address*.\"\"\"
    ...

def decompile_function(address: int) -> list[str]:
    \"\"\"Return C pseudocode lines for the function at *address*.\"\"\"
    ...

def get_function_signature(address: int) -> str | None:
    \"\"\"Return the type signature of the function at *address*.\"\"\"
    ...

def get_callers(address: int) -> list[dict[str, Any]]:
    \"\"\"Return functions that call the function at *address*.\"\"\"
    ...

def get_callees(address: int) -> list[dict[str, Any]]:
    \"\"\"Return functions called by the function at *address*.\"\"\"
    ...

def get_basic_blocks(address: int) -> list[dict[str, Any]]:
    \"\"\"Return the control-flow graph of the function at *address*.\"\"\"
    ...

# --- Cross-references ---

def get_xrefs_to(address: int) -> list[dict[str, Any]]:
    \"\"\"Return cross-references TO *address*.\"\"\"
    ...

def get_xrefs_from(address: int) -> list[dict[str, Any]]:
    \"\"\"Return cross-references FROM *address*.\"\"\"
    ...

# --- Strings ---

def enumerate_strings() -> list[dict[str, Any]]:
    \"\"\"Return all detected strings in the binary.\"\"\"
    ...

def get_string_at(address: int) -> str | None:
    \"\"\"Read the null-terminated C string at *address*.\"\"\"
    ...

# --- Segments ---

def enumerate_segments() -> list[dict[str, Any]]:
    \"\"\"Return all memory segments.\"\"\"
    ...

# --- Names / symbols ---

def enumerate_names() -> list[dict[str, Any]]:
    \"\"\"Return all named addresses (symbols / labels).\"\"\"
    ...

def get_name_at(address: int) -> str | None:
    \"\"\"Return the symbol name at *address*, or None.\"\"\"
    ...

def demangle_name(name: str) -> str:
    \"\"\"Demangle a C++ mangled *name*.\"\"\"
    ...

# --- Imports & entries ---

def enumerate_imports() -> list[dict[str, Any]]:
    \"\"\"Return all imported functions.\"\"\"
    ...

def enumerate_entries() -> list[dict[str, Any]]:
    \"\"\"Return all entry points / exports.\"\"\"
    ...

# --- Bytes / memory ---

def read_bytes(address: int, size: int) -> list[int]:
    \"\"\"Return *size* bytes at *address* as a list of ints.\"\"\"
    ...

def find_bytes(pattern: list[int]) -> list[int]:
    \"\"\"Find all occurrences of a byte *pattern*; return matching addresses.\"\"\"
    ...

def get_disassembly_at(address: int) -> str | None:
    \"\"\"Return the disassembly text for the single instruction at *address*.\"\"\"
    ...

def get_instruction_at(address: int) -> dict[str, Any] | None:
    \"\"\"Return structured instruction data at *address*.\"\"\"
    ...

# --- Address classification ---

def is_code_at(address: int) -> bool:
    \"\"\"Return True if *address* contains code.\"\"\"
    ...

def is_data_at(address: int) -> bool:
    \"\"\"Return True if *address* contains defined data.\"\"\"
    ...

def is_valid_address(address: int) -> bool:
    \"\"\"Return True if *address* is mapped in the database.\"\"\"
    ...

# --- Comments ---

def get_comment_at(address: int) -> str | None:
    \"\"\"Return the comment at *address*, or None.\"\"\"
    ...

# --- Utilities ---

def random_int(low: int, high: int) -> int:
    \"\"\"Return a random integer in [low, high].\"\"\"
    ...
"""


# ---------------------------------------------------------------------------
# Function names  (must match TYPE_STUBS above)
# ---------------------------------------------------------------------------

FUNCTION_NAMES: list[str] = [
    # Database metadata
    "get_binary_info",
    # Function enumeration & lookup
    "enumerate_functions",
    "get_function_by_name",
    # Function analysis
    "disassemble_function",
    "decompile_function",
    "get_function_signature",
    "get_callers",
    "get_callees",
    "get_basic_blocks",
    # Cross-references
    "get_xrefs_to",
    "get_xrefs_from",
    # Strings
    "enumerate_strings",
    "get_string_at",
    # Segments
    "enumerate_segments",
    # Names / symbols
    "enumerate_names",
    "get_name_at",
    "demangle_name",
    # Imports & entries
    "enumerate_imports",
    "enumerate_entries",
    # Bytes / memory
    "read_bytes",
    "find_bytes",
    "get_disassembly_at",
    "get_instruction_at",
    # Address classification
    "is_code_at",
    "is_data_at",
    "is_valid_address",
    # Comments
    "get_comment_at",
    # Utilities
    "random_int",
]


# ---------------------------------------------------------------------------
# IDA-backed function builder
# ---------------------------------------------------------------------------


def build_ida_functions(db: Any) -> dict[str, Callable[..., Any]]:
    """Build the IDA-backed function implementations.

    Each function serializes IDA domain objects into plain Python types
    (dicts, lists, ints, strings) so they can cross process, sandbox, or
    RPC boundaries.

    Args:
        db: An open ``ida_domain.Database``.

    Returns:
        Mapping of function name to implementation callable.

    Example::

        from ida_domain import Database
        from ida_codemode_api import build_ida_functions

        with Database.open(path, options) as db:
            fns = build_ida_functions(db)
            info = fns["get_binary_info"]()
            print(info["architecture"])
    """

    # -----------------------------------------------------------------------
    # Database metadata
    # -----------------------------------------------------------------------

    def get_binary_info() -> dict[str, Any]:
        """Return global metadata about the binary under analysis.

        Returns:
            A dict with keys:

            - **path** (*str*) – file system path of the input file.
            - **module** (*str*) – short module / file name.
            - **architecture** (*str*) – processor family (e.g. ``"metapc"``).
            - **bitness** (*int*) – address size: 32 or 64.
            - **format** (*str*) – file format description
              (e.g. ``"ELF64 for x86-64 (Shared object)"``).
            - **base_address** (*int*) – image base address.
            - **entry_point** (*int*) – program entry point address.
            - **minimum_ea** (*int*) – lowest mapped effective address.
            - **maximum_ea** (*int*) – highest mapped effective address.
            - **filesize** (*int*) – size of the input file in bytes.
            - **md5** (*str*) – MD5 hex digest of the input file.
            - **sha256** (*str*) – SHA-256 hex digest of the input file.
            - **crc32** (*int*) – CRC-32 checksum of the input file.

        Example::

            info = get_binary_info()
            print(info["module"] + " (" + info["architecture"] + ", "
                  + str(info["bitness"]) + "-bit)")
            # => "sample.exe (metapc, 32-bit)"
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

    # -----------------------------------------------------------------------
    # Function enumeration & lookup
    # -----------------------------------------------------------------------

    def enumerate_functions() -> list[dict[str, Any]]:
        """Return every function in the database.

        Returns:
            A list of dicts, each with keys:

            - **address** (*int*) – function start address.
            - **name** (*str*) – function name.
            - **size** (*int*) – function size in bytes.

        Example::

            functions = enumerate_functions()
            for f in functions:
                print(hex(f["address"]) + " " + f["name"]
                      + " (" + str(f["size"]) + " bytes)")
        """
        results: list[dict[str, Any]] = []
        for func in db.functions:
            results.append({
                "address": int(func.start_ea),
                "name": str(db.functions.get_name(func)),
                "size": int(func.size() if callable(func.size) else func.size),
            })
        return results

    def get_function_by_name(name: str) -> dict[str, Any] | None:
        """Look up a function by its symbolic *name*.

        Args:
            name: The exact function name to search for.

        Returns:
            A dict with ``address``, ``name``, and ``size`` keys,
            or ``None`` if no function with that name exists.

        Example::

            fn = get_function_by_name("main")
            if fn is not None:
                print(fn["name"] + " at " + hex(fn["address"]))
        """
        func = db.functions.get_function_by_name(name)
        if func is None:
            return None
        return {
            "address": int(func.start_ea),
            "name": str(db.functions.get_name(func)),
            "size": int(func.size() if callable(func.size) else func.size),
        }

    # -----------------------------------------------------------------------
    # Function analysis
    # -----------------------------------------------------------------------

    def disassemble_function(address: int) -> list[str]:
        """Return the disassembly listing for the function at *address*.

        Each element is one line of disassembly text as IDA formats it
        (e.g. ``"mov     rax, [rbp+var_8]"``).

        Args:
            address: Start address of the target function.

        Returns:
            List of disassembly line strings, or an empty list if no
            function exists at *address*.

        Example::

            fn = get_function_by_name("main")
            if fn is not None:
                for line in disassemble_function(fn["address"]):
                    print(line)
        """
        try:
            func = db.functions.get_at(address)
        except Exception:
            return []
        if func is None:
            return []
        return list(db.functions.get_disassembly(func))

    def decompile_function(address: int) -> list[str]:
        """Return C pseudocode for the function at *address*.

        Requires the Hex-Rays decompiler.  When the decompiler is not
        available or decompilation fails, an empty list is returned.

        Args:
            address: Start address of the target function.

        Returns:
            List of pseudocode line strings, or ``[]`` when
            decompilation is unavailable.

        Example::

            fn = get_function_by_name("main")
            if fn is not None:
                pseudocode = decompile_function(fn["address"])
                for line in pseudocode:
                    print(line)
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

    def get_function_signature(address: int) -> str | None:
        """Return the type signature of the function at *address*.

        The signature is a C-style declaration string such as
        ``"int __cdecl main(int argc, const char **argv)"``.

        Args:
            address: Start address of the target function.

        Returns:
            Signature string, or ``None`` if no type information is
            available or no function exists at *address*.

        Example::

            fn = get_function_by_name("main")
            if fn is not None:
                sig = get_function_signature(fn["address"])
                print("Signature: " + str(sig))
        """
        try:
            func = db.functions.get_at(address)
        except Exception:
            return None
        if func is None:
            return None
        sig = db.functions.get_signature(func)
        return str(sig) if sig is not None else None

    def get_callers(address: int) -> list[dict[str, Any]]:
        """Return functions that contain a call to the function at *address*.

        Args:
            address: Start address of the target function.

        Returns:
            A list of dicts, each with keys:

            - **address** (*int*) – caller function start address.
            - **name** (*str*) – caller function name.

        Example::

            fn = get_function_by_name("CreateFileA")
            if fn is not None:
                for caller in get_callers(fn["address"]):
                    print(caller["name"] + " calls CreateFileA")
        """
        try:
            func = db.functions.get_at(address)
        except Exception:
            return []
        if func is None:
            return []
        results: list[dict[str, Any]] = []
        for caller in db.functions.get_callers(func):
            results.append({
                "address": int(caller.start_ea),
                "name": str(db.functions.get_name(caller)),
            })
        return results

    def get_callees(address: int) -> list[dict[str, Any]]:
        """Return functions called by the function at *address*.

        Args:
            address: Start address of the calling function.

        Returns:
            A list of dicts, each with keys:

            - **address** (*int*) – callee function start address.
            - **name** (*str*) – callee function name.

        Example::

            fn = get_function_by_name("main")
            if fn is not None:
                for callee in get_callees(fn["address"]):
                    print("main calls " + callee["name"])
        """
        try:
            func = db.functions.get_at(address)
        except Exception:
            return []
        if func is None:
            return []
        results: list[dict[str, Any]] = []
        for callee in db.functions.get_callees(func):
            results.append({
                "address": int(callee.start_ea),
                "name": str(db.functions.get_name(callee)),
            })
        return results

    def get_basic_blocks(address: int) -> list[dict[str, Any]]:
        """Return the control-flow graph of the function at *address*.

        Each basic block is a maximal sequence of instructions with a
        single entry point and a single exit point.

        Args:
            address: Start address of the target function.

        Returns:
            A list of dicts, each with keys:

            - **start** (*int*) – block start address.
            - **end** (*int*) – block end address (exclusive).
            - **successors** (*list[int]*) – start addresses of successor
              blocks.
            - **predecessors** (*list[int]*) – start addresses of predecessor
              blocks.

            Returns ``[]`` if no function exists at *address*.

        Example::

            fn = get_function_by_name("main")
            if fn is not None:
                blocks = get_basic_blocks(fn["address"])
                print("Basic blocks: " + str(len(blocks)))
                for b in blocks:
                    print(hex(b["start"]) + "-" + hex(b["end"])
                          + " -> " + str(len(b["successors"])) + " succs")
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
        results: list[dict[str, Any]] = []
        for block in flowchart:
            results.append({
                "start": int(block.start_ea),
                "end": int(block.end_ea),
                "successors": [int(s.start_ea) for s in block.succs()],
                "predecessors": [int(p.start_ea) for p in block.preds()],
            })
        return results

    # -----------------------------------------------------------------------
    # Cross-references
    # -----------------------------------------------------------------------

    def get_xrefs_to(address: int) -> list[dict[str, Any]]:
        """Return all cross-references that target *address*.

        Args:
            address: The destination address to query.

        Returns:
            A list of dicts, each with keys:

            - **from_address** (*int*) – source address of the reference.
            - **type** (*str*) – reference type name
              (e.g. ``"CALL_NEAR"``, ``"OFFSET"``).
            - **is_call** (*bool*) – ``True`` if this is a call reference.
            - **is_jump** (*bool*) – ``True`` if this is a jump reference.

        Example::

            fn = get_function_by_name("main")
            if fn is not None:
                for xref in get_xrefs_to(fn["address"]):
                    tag = " [CALL]" if xref["is_call"] else ""
                    print(hex(xref["from_address"]) + tag)
        """
        results: list[dict[str, Any]] = []
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

    def get_xrefs_from(address: int) -> list[dict[str, Any]]:
        """Return all cross-references originating at *address*.

        Args:
            address: The source address to query.

        Returns:
            A list of dicts, each with keys:

            - **to_address** (*int*) – destination address of the reference.
            - **type** (*str*) – reference type name.
            - **is_call** (*bool*) – ``True`` if this is a call reference.
            - **is_jump** (*bool*) – ``True`` if this is a jump reference.

        Example::

            fn = get_function_by_name("main")
            if fn is not None:
                for xref in get_xrefs_from(fn["address"]):
                    print("-> " + hex(xref["to_address"])
                          + " (" + xref["type"] + ")")
        """
        results: list[dict[str, Any]] = []
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

    # -----------------------------------------------------------------------
    # Strings
    # -----------------------------------------------------------------------

    def enumerate_strings() -> list[dict[str, Any]]:
        """Return every string detected by IDA in the binary.

        Returns:
            A list of dicts, each with keys:

            - **address** (*int*) – address of the string.
            - **length** (*int*) – character count.
            - **type** (*str*) – string type name (e.g. ``"C"``, ``"C_16"``).
            - **value** (*str*) – the string contents decoded as UTF-8.

        Example::

            strings = enumerate_strings()
            for s in strings:
                if "password" in s["value"].lower():
                    print(hex(s["address"]) + ": " + s["value"])
        """
        results: list[dict[str, Any]] = []
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
        """Read the null-terminated C string starting at *address*.

        Args:
            address: Address of the first byte of the string.

        Returns:
            The string contents, or ``None`` if no string is found.

        Example::

            strings = enumerate_strings()
            if len(strings) > 0:
                value = get_string_at(strings[0]["address"])
                print("First string: " + str(value))
        """
        try:
            result = db.bytes.get_cstring_at(address)
            return str(result) if result is not None else None
        except (RuntimeError, Exception):
            return None

    # -----------------------------------------------------------------------
    # Segments
    # -----------------------------------------------------------------------

    def enumerate_segments() -> list[dict[str, Any]]:
        """Return every memory segment in the database.

        Returns:
            A list of dicts, each with keys:

            - **name** (*str*) – segment name (e.g. ``".text"``).
            - **start** (*int*) – segment start address.
            - **end** (*int*) – segment end address (exclusive).
            - **size** (*int*) – segment size in bytes.
            - **permissions** (*int*) – permission bitmask (R=4, W=2, X=1).
            - **class** (*str*) – segment class (e.g. ``"CODE"``, ``"DATA"``).
            - **bitness** (*int*) – segment address width (16, 32, or 64).

        Example::

            for seg in enumerate_segments():
                print(seg["name"] + " " + hex(seg["start"])
                      + "-" + hex(seg["end"])
                      + " (" + seg["class"] + ")")
        """
        results: list[dict[str, Any]] = []
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

    # -----------------------------------------------------------------------
    # Names / symbols
    # -----------------------------------------------------------------------

    def enumerate_names() -> list[dict[str, Any]]:
        """Return all named addresses (symbols and labels) in the database.

        Returns:
            A list of dicts, each with keys:

            - **address** (*int*) – the named address.
            - **name** (*str*) – the symbol name.

        Example::

            names = enumerate_names()
            print("Named symbols: " + str(len(names)))
            for n in names:
                print(hex(n["address"]) + " " + n["name"])
        """
        results: list[dict[str, Any]] = []
        for ea, name in db.names:
            results.append({
                "address": int(ea),
                "name": str(name),
            })
        return results

    def get_name_at(address: int) -> str | None:
        """Return the symbol name at *address*.

        Args:
            address: The address to query.

        Returns:
            The name string, or ``None`` if the address has no name.

        Example::

            name = get_name_at(0x401000)
            if name is not None:
                print("Symbol at 0x401000: " + name)
        """
        try:
            result = db.names.get_at(address)
        except Exception:
            return None
        return str(result) if result else None

    def demangle_name(name: str) -> str:
        """Demangle a C++ mangled symbol *name*.

        For example, ``"_Z3addii"`` becomes ``"add(int,int)"``.

        Args:
            name: The mangled name string.

        Returns:
            The demangled name.  Returns *name* unchanged if it is not
            a valid mangled name.

        Example::

            names = enumerate_names()
            for n in names:
                demangled = demangle_name(n["name"])
                if demangled != n["name"]:
                    print(n["name"] + " -> " + demangled)
        """
        result = db.names.demangle_name(name)
        return str(result) if result else str(name)

    # -----------------------------------------------------------------------
    # Imports & entry points
    # -----------------------------------------------------------------------

    def enumerate_imports() -> list[dict[str, Any]]:
        """Return all imported functions / symbols.

        Returns:
            A list of dicts, each with keys:

            - **address** (*int*) – import address (IAT slot or PLT entry).
            - **name** (*str*) – imported symbol name.
            - **module** (*str*) – name of the providing module / library.
            - **ordinal** (*int*) – import ordinal number.

        Example::

            imports = enumerate_imports()
            for imp in imports:
                print(imp["module"] + "!" + imp["name"])
        """
        results: list[dict[str, Any]] = []
        for imp in db.imports.get_all_imports():
            results.append({
                "address": int(imp.address),
                "name": str(imp.name),
                "module": str(imp.module_name),
                "ordinal": int(imp.ordinal),
            })
        return results

    def enumerate_entries() -> list[dict[str, Any]]:
        """Return all entry points and exported symbols.

        Returns:
            A list of dicts, each with keys:

            - **ordinal** (*int*) – entry point ordinal.
            - **address** (*int*) – entry point address.
            - **name** (*str*) – entry point name.
            - **forwarder** (*str | None*) – forwarded name, if any.

        Example::

            entries = enumerate_entries()
            for e in entries:
                print("Entry: " + e["name"] + " at " + hex(e["address"]))
        """
        results: list[dict[str, Any]] = []
        for entry in db.entries:
            forwarder: str | None = None
            if hasattr(entry, "has_forwarder") and entry.has_forwarder:
                forwarder = str(entry.forwarder_name)
            results.append({
                "ordinal": int(entry.ordinal),
                "address": int(entry.address),
                "name": str(entry.name),
                "forwarder": forwarder,
            })
        return results

    # -----------------------------------------------------------------------
    # Bytes / memory
    # -----------------------------------------------------------------------

    def read_bytes(address: int, size: int) -> list[int]:
        """Read raw bytes from the database.

        Args:
            address: Start address to read from.
            size: Number of bytes to read.

        Returns:
            A list of integer byte values (0-255).  Returns ``[]`` if
            *address* is unmapped.

        Example::

            fn = get_function_by_name("main")
            if fn is not None:
                raw = read_bytes(fn["address"], 16)
                parts = []
                for b in raw:
                    if b < 16:
                        parts.append("0" + hex(b)[2:])
                    else:
                        parts.append(hex(b)[2:])
                print(" ".join(parts))
        """
        try:
            data = db.bytes.get_bytes_at(address, size)
        except Exception:
            return []
        if data is None:
            return []
        return list(data)

    def find_bytes(pattern: list[int]) -> list[int]:
        """Search the entire database for a byte pattern.

        The *pattern* is a list of integer byte values
        (e.g. ``[0x55, 0x48, 0x89, 0xe5]`` for a typical x86-64
        function prologue).

        Args:
            pattern: Byte values to search for.

        Returns:
            A list of addresses where the pattern was found.

        Example::

            # Find x86 "push ebp; mov ebp, esp" prologue
            hits = find_bytes([0x55, 0x8B, 0xEC])
            for addr in hits:
                name = get_name_at(addr)
                if name is not None:
                    print(hex(addr) + " " + name)
        """
        return [int(ea) for ea in db.bytes.find_binary_sequence(bytes(pattern))]

    def get_disassembly_at(address: int) -> str | None:
        """Return the disassembly text for the single instruction at *address*.

        Unlike :func:`disassemble_function` which returns an entire function,
        this returns just one instruction line.

        Args:
            address: Address of the instruction.

        Returns:
            Disassembly string, or ``None`` if *address* does not contain
            a recognized instruction.

        Example::

            fn = get_function_by_name("main")
            if fn is not None:
                text = get_disassembly_at(fn["address"])
                print("First instruction: " + str(text))
        """
        try:
            result = db.bytes.get_disassembly_at(address)
            return str(result) if result is not None else None
        except (RuntimeError, Exception):
            return None

    def get_instruction_at(address: int) -> dict[str, Any] | None:
        """Return structured data for the instruction at *address*.

        Args:
            address: Address of the instruction to decode.

        Returns:
            A dict with keys:

            - **address** (*int*) – instruction address.
            - **size** (*int*) – instruction length in bytes.
            - **mnemonic** (*str*) – opcode mnemonic (e.g. ``"mov"``).
            - **disassembly** (*str*) – full disassembly text.
            - **is_call** (*bool*) – ``True`` if this is a call instruction.

            Returns ``None`` if no instruction could be decoded.

        Example::

            fn = get_function_by_name("main")
            if fn is not None:
                insn = get_instruction_at(fn["address"])
                if insn is not None:
                    print(insn["mnemonic"] + " (size="
                          + str(insn["size"]) + ")")
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

    # -----------------------------------------------------------------------
    # Address classification
    # -----------------------------------------------------------------------

    def is_code_at(address: int) -> bool:
        """Return ``True`` if *address* contains executable code.

        Args:
            address: The address to classify.

        Example::

            fn = get_function_by_name("main")
            if fn is not None:
                print("is code: " + str(is_code_at(fn["address"])))
                # => "is code: True"
        """
        try:
            return bool(db.bytes.is_code_at(address))
        except Exception:
            return False

    def is_data_at(address: int) -> bool:
        """Return ``True`` if *address* contains defined data.

        Args:
            address: The address to classify.

        Example::

            strings = enumerate_strings()
            if len(strings) > 0:
                print("is data: "
                      + str(is_data_at(strings[0]["address"])))
        """
        try:
            return bool(db.bytes.is_data_at(address))
        except Exception:
            return False

    def is_valid_address(address: int) -> bool:
        """Return ``True`` if *address* is mapped in the database.

        Args:
            address: The address to check.

        Example::

            print(is_valid_address(0x401000))   # True (if mapped)
            print(is_valid_address(0xDEADDEAD)) # False
        """
        return bool(db.is_valid_ea(address))

    # -----------------------------------------------------------------------
    # Comments
    # -----------------------------------------------------------------------

    def get_comment_at(address: int) -> str | None:
        """Return the analyst comment at *address*.

        Args:
            address: The address to query.

        Returns:
            The comment string, or ``None`` if no comment exists.

        Example::

            functions = enumerate_functions()
            for f in functions:
                comment = get_comment_at(f["address"])
                if comment is not None:
                    print(f["name"] + ': "' + comment + '"')
        """
        try:
            result = db.comments.get_at(address)
        except Exception:
            return None
        return str(result) if result else None

    # -----------------------------------------------------------------------
    # Utilities
    # -----------------------------------------------------------------------

    def random_int(low: int, high: int) -> int:
        """Return a random integer *n* such that ``low <= n <= high``.

        Args:
            low: Inclusive lower bound.
            high: Inclusive upper bound.

        Example::

            functions = enumerate_functions()
            idx = random_int(0, len(functions) - 1)
            print("Random function: " + functions[idx]["name"])
        """
        return _random.randint(low, high)

    # -----------------------------------------------------------------------
    # Collect and return
    # -----------------------------------------------------------------------

    return {
        # Database metadata
        "get_binary_info": get_binary_info,
        # Function enumeration & lookup
        "enumerate_functions": enumerate_functions,
        "get_function_by_name": get_function_by_name,
        # Function analysis
        "disassemble_function": disassemble_function,
        "decompile_function": decompile_function,
        "get_function_signature": get_function_signature,
        "get_callers": get_callers,
        "get_callees": get_callees,
        "get_basic_blocks": get_basic_blocks,
        # Cross-references
        "get_xrefs_to": get_xrefs_to,
        "get_xrefs_from": get_xrefs_from,
        # Strings
        "enumerate_strings": enumerate_strings,
        "get_string_at": get_string_at,
        # Segments
        "enumerate_segments": enumerate_segments,
        # Names / symbols
        "enumerate_names": enumerate_names,
        "get_name_at": get_name_at,
        "demangle_name": demangle_name,
        # Imports & entries
        "enumerate_imports": enumerate_imports,
        "enumerate_entries": enumerate_entries,
        # Bytes / memory
        "read_bytes": read_bytes,
        "find_bytes": find_bytes,
        "get_disassembly_at": get_disassembly_at,
        "get_instruction_at": get_instruction_at,
        # Address classification
        "is_code_at": is_code_at,
        "is_data_at": is_data_at,
        "is_valid_address": is_valid_address,
        # Comments
        "get_comment_at": get_comment_at,
        # Utilities
        "random_int": random_int,
    }


def api_reference() -> str:
    """Return the function-reference tables as markdown.

    A prompt fragment listing every API function, its return type, and a
    short description.  Suitable for inclusion in LLM system prompts or
    documentation.
    """
    return (_PROMPTS_DIR / "api_reference.md").read_text()
