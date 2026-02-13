"""IDA Codemode API.

Portable analysis APIs for IDA Pro suitable for sandboxed code execution,
JSON-RPC exposure, and LLM tool use.

For fallible operations, return values are ``SuccessPayload | ApiError``:

- success payloads do **not** include a status discriminator
- failures use ``{"error": "..."}``

Use :func:`create_api_from_database` to build concrete callables bound to an
open ``ida_domain.Database``.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from types import NoneType, UnionType
from typing import Any, Callable, Literal, Union, get_args, get_origin, get_type_hints

from . import api_types


TYPE_STUBS_PATH = Path(api_types.__file__ or "").resolve()
"""Filesystem path of the authoritative stub module."""

TYPE_STUBS = TYPE_STUBS_PATH.read_text(encoding="utf-8")
"""Authoritative API stubs consumed by Monty type checking."""


FUNCTION_NAMES: list[str] = [
    "help",
    "get_database_metadata",
    "get_functions",
    "get_function_by_name",
    "get_function_at",
    "get_function_disassembly_at",
    "decompile_function_at",
    "get_function_callers",
    "get_function_callees",
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

def _collect_typed_dicts(module: Any) -> dict[str, Any]:
    typed_dicts: dict[str, Any] = {}
    for name, value in vars(module).items():
        if not isinstance(value, type):
            continue
        if not issubclass(value, dict):
            continue
        if not hasattr(value, "__total__"):
            continue
        typed_dicts[name] = value
    return typed_dicts


_TYPED_DICTS: dict[str, Any] = _collect_typed_dicts(api_types)


def _render_type(annotation: Any) -> str:
    origin = get_origin(annotation)

    if origin in (Union, UnionType):
        parts = [_render_type(arg) for arg in get_args(annotation) if arg is not api_types.ApiError]
        if len(parts) == 1:
            return parts[0]
        return " | ".join(parts)

    if isinstance(annotation, type) and annotation in _TYPED_DICTS.values():
        hints = get_type_hints(annotation, include_extras=True)
        fields: list[str] = []
        for key in annotation.__annotations__.keys():
            fields.append(f"{key}: {_render_type(hints[key])}")
        return "{" + ", ".join(fields) + "}"

    if origin is list:
        args = get_args(annotation)
        if len(args) == 1:
            return f"list[{_render_type(args[0])}]"
        return "list[Any]"

    if origin is Literal:
        values = ", ".join(repr(v) for v in get_args(annotation))
        return f"Literal[{values}]"

    if annotation is NoneType:
        return "None"

    if annotation is Any:
        return "Any"

    if isinstance(annotation, type):
        return annotation.__name__

    return str(annotation)


def _implementation_functions_for_reference() -> dict[str, Callable[..., Any]]:
    """Return implementation callables used for API-reference introspection."""
    return create_api_from_database(object())


def _function_success_return_shape(
    function_name: str,
    implementation_functions: dict[str, Callable[..., Any]],
) -> str:
    implementation = implementation_functions.get(function_name)
    if implementation is not None:
        try:
            hints = get_type_hints(implementation, include_extras=True)
        except Exception:
            hints = {}

        return_annotation = hints.get("return")
        if return_annotation is not None:
            return _render_type(return_annotation)

    function = getattr(api_types, function_name)
    hints = get_type_hints(function, include_extras=True)
    return_annotation = hints.get("return", Any)
    return _render_type(return_annotation)


def _api_rows_from_implementation(
    implementation_functions: dict[str, Callable[..., Any]],
) -> list[tuple[str, str, str]]:
    rows: dict[str, tuple[str, str, str]] = {}

    for function_name in FUNCTION_NAMES:
        implementation = implementation_functions.get(function_name)
        if implementation is None:
            continue

        signature = f"{function_name}{inspect.signature(implementation)}"

        declaration = getattr(api_types, function_name, None)
        declaration_doc = inspect.getdoc(declaration) if declaration else None
        doc = declaration_doc or inspect.getdoc(implementation) or ""
        description = doc.strip().splitlines()[0] if doc.strip() else ""

        rows[function_name] = (function_name, signature, description)

    return [rows[name] for name in FUNCTION_NAMES if name in rows]


def create_api_from_database(db: Any) -> dict[str, Callable[..., Any]]:
    """Build API callables backed by an open ``ida_domain.Database``.

    Args:
        db: Open database object from ``ida_domain``.

    Returns:
        Mapping from API name to callable implementation.
    """

    def _serialize_function(func: Any) -> api_types.FunctionInfo:
        name = str(db.functions.get_name(func))
        demangled = db.names.demangle_name(name)
        if demangled:
            name = str(demangled)

        try:
            sig = db.functions.get_signature(func)
            signature = str(sig) if sig else ""
        except Exception:
            signature = ""

        try:
            comment = db.comments.get_at(func.start_ea)
            comment_str = str(comment) if comment else ""
        except Exception:
            comment_str = ""

        try:
            repeatable = db.comments.get_repeatable_at(func.start_ea)
            repeatable_str = str(repeatable) if repeatable else ""
        except Exception:
            repeatable_str = ""

        flags: api_types.FunctionFlags = {
            "noreturn": bool(func.flags & 0x1) if hasattr(func, "flags") else False,
            "library": bool(func.flags & 0x4) if hasattr(func, "flags") else False,
            "thunk": bool(func.flags & 0x80) if hasattr(func, "flags") else False,
        }

        return {
            "address": int(func.start_ea),
            "name": name,
            "size": int(func.size() if callable(func.size) else func.size),
            "signature": signature,
            "flags": flags,
            "comment": comment_str,
            "repeatable_comment": repeatable_str,
        }

    def _error(message: str) -> api_types.ApiError:
        return {
            "error": str(message),
        }

    def _error_from_exc(context: str, exc: Exception) -> api_types.ApiError:
        return _error(f"{context}: {type(exc).__name__}: {exc}")

    def _lookup_function_containing(address: int, *, context: str) -> tuple[Any | None, api_types.ApiError | None]:
        try:
            func = db.functions.get_at(address)
        except Exception as exc:
            return None, _error_from_exc(f"{context}: failed to resolve function at {address:#x}", exc)

        if func is None:
            return None, _error(f"{context}: no function contains address {address:#x}")

        return func, None

    def _lookup_function_start(address: int, *, context: str) -> tuple[Any | None, api_types.ApiError | None]:
        func, err = _lookup_function_containing(address, context=context)
        if err is not None:
            return None, err

        if func is None:
            return None, _error(f"{context}: no function contains address {address:#x}")

        if int(func.start_ea) != int(address):
            return None, _error(f"{context}: address {address:#x} is not a function start")

        return func, None

    def help(api):
        if not isinstance(api, str):
            return _error(f"api must be str, got {type(api).__name__}")

        callback_name = api.strip()
        if callback_name.endswith("()"):
            callback_name = callback_name[:-2]

        if not callback_name:
            return _error("api must be a non-empty callback name")

        if callback_name not in FUNCTION_NAMES:
            available = ", ".join(FUNCTION_NAMES)
            return _error(f"unknown callback {callback_name!r}; available callbacks: {available}")

        declaration = getattr(api_types, callback_name, None)
        if declaration is None or not callable(declaration):
            return _error(f"callback {callback_name!r} is unavailable")

        try:
            signature = inspect.signature(declaration)
        except Exception as exc:
            return _error_from_exc(f"failed to inspect callback signature for {callback_name!r}", exc)

        try:
            hints = get_type_hints(declaration, include_extras=True)
        except Exception:
            hints = {}

        rendered_parameters: list[str] = []
        for parameter in signature.parameters.values():
            annotation = hints.get(parameter.name)
            if annotation is None:
                rendered_parameters.append(parameter.name)
                continue

            rendered_parameters.append(f"{parameter.name}: {_render_type(annotation)}")

        return_annotation = hints.get("return", Any)
        rendered_return = _render_type(return_annotation)
        rendered_signature = f"{callback_name}({', '.join(rendered_parameters)})"

        doc = inspect.getdoc(declaration)
        if not doc:
            return _error(f"callback {callback_name!r} has no documentation")

        return {
            "documentation": f"{rendered_signature} -> {rendered_return}\n\n{doc}",
        }

    def get_database_metadata():
        try:
            return {
                "input_file_path": str(db.path),
                "module": str(db.module),
                "architecture": str(db.architecture),
                "bitness": int(db.bitness),
                "format": str(db.format),
                "base_address": int(db.base_address),
                "entry_point": int(db.start_ip),
                "minimum_ea": int(db.minimum_ea),
                "maximum_ea": int(db.maximum_ea),
                "input_file_size": int(db.filesize),
                "input_file_md5": str(db.md5),
                "input_file_sha256": str(db.sha256),
            }
        except Exception as exc:
            return _error_from_exc("failed to read database metadata", exc)

    def get_functions():
        try:
            return {
                "functions": [_serialize_function(func) for func in db.functions],
            }
        except Exception as exc:
            return _error_from_exc("failed to enumerate functions", exc)

    def get_function_by_name(name):
        try:
            func = db.functions.get_function_by_name(name)
        except Exception as exc:
            return _error_from_exc(f"failed to look up function named {name!r}", exc)

        if func is None:
            try:
                for candidate in db.functions:
                    candidate_name = str(db.functions.get_name(candidate))
                    demangled = db.names.demangle_name(candidate_name)
                    if demangled and str(demangled) == name:
                        func = candidate
                        break
            except Exception:
                pass

        if func is None:
            return _error(f"no function named {name!r}")

        return _serialize_function(func)

    def get_function_at(address):
        func, err = _lookup_function_start(address, context="function lookup")
        if err is not None:
            return err

        return _serialize_function(func)

    def get_function_disassembly_at(address):
        func, err = _lookup_function_containing(address, context="function disassembly")
        if err is not None:
            return err

        try:
            disassembly = db.functions.get_disassembly(func)
        except Exception as exc:
            return _error_from_exc(f"failed to disassemble function at {address:#x}", exc)

        if disassembly is None:
            return _error(f"no disassembly available for function at {address:#x}")

        return {
            "disassembly": [str(line) for line in disassembly],
        }

    def decompile_function_at(address):
        func, err = _lookup_function_containing(address, context="function decompilation")
        if err is not None:
            return err

        try:
            result = db.functions.get_pseudocode(func)
        except Exception as exc:
            return _error_from_exc(
                f"failed to decompile function at {address:#x} (decompiler unavailable or failed)",
                exc,
            )

        if result is None:
            return _error(f"no pseudocode available for function at {address:#x}")

        return {
            "pseudocode": [str(line) for line in result],
        }

    def get_function_callers(address):
        func, err = _lookup_function_containing(address, context="caller analysis")
        if err is not None:
            return err

        try:
            callers = db.functions.get_callers(func)
            items = [_serialize_function(caller) for caller in callers]
        except Exception as exc:
            return _error_from_exc(f"failed to enumerate callers for function at {address:#x}", exc)

        return {
            "callers": items,
        }

    def get_function_callees(address):
        func, err = _lookup_function_containing(address, context="callee analysis")
        if err is not None:
            return err

        try:
            callees = db.functions.get_callees(func)
            items = [_serialize_function(callee) for callee in callees]
        except Exception as exc:
            return _error_from_exc(f"failed to enumerate callees for function at {address:#x}", exc)

        return {
            "callees": items,
        }

    def get_basic_blocks_at(address):
        func, err = _lookup_function_containing(address, context="basic-block analysis")
        if err is not None:
            return err

        try:
            flowchart = db.functions.get_flowchart(func)
        except Exception as exc:
            return _error_from_exc(f"failed to build CFG for function at {address:#x}", exc)

        if flowchart is None:
            return _error(f"no control-flow graph available for function at {address:#x}")

        try:
            items = []
            for block in flowchart:
                items.append({
                    "start": int(block.start_ea),
                    "end": int(block.end_ea),
                    "successors": [int(s.start_ea) for s in block.succs()],
                    "predecessors": [int(p.start_ea) for p in block.preds()],
                })
        except Exception as exc:
            return _error_from_exc(f"failed while serializing CFG for function at {address:#x}", exc)

        return {
            "basic_blocks": items,
        }

    def get_xrefs_to_at(address):
        try:
            items = []
            for xref in db.xrefs.to_ea(address):
                items.append({
                    "from_address": int(xref.from_ea),
                    "type": str(xref.type.name),
                    "is_call": bool(xref.is_call),
                    "is_jump": bool(xref.is_jump),
                })
        except Exception as exc:
            return _error_from_exc(f"failed to enumerate xrefs to {address:#x}", exc)

        return {
            "xrefs": items,
        }

    def get_xrefs_from_at(address):
        try:
            items = []
            for xref in db.xrefs.from_ea(address):
                items.append({
                    "to_address": int(xref.to_ea),
                    "type": str(xref.type.name),
                    "is_call": bool(xref.is_call),
                    "is_jump": bool(xref.is_jump),
                })
        except Exception as exc:
            return _error_from_exc(f"failed to enumerate xrefs from {address:#x}", exc)

        return {
            "xrefs": items,
        }

    def get_strings():
        try:
            items = []
            for s in db.strings:
                value = s.contents
                if isinstance(value, (bytes, bytearray)):
                    value = value.decode("utf-8", errors="replace")
                items.append({
                    "address": int(s.address),
                    "length": int(s.length),
                    "type": str(s.type.name) if hasattr(s.type, "name") else str(s.type),
                    "value": str(value),
                })
        except Exception as exc:
            return _error_from_exc("failed to enumerate strings", exc)

        return {
            "strings": items,
        }

    def get_string_at(address):
        try:
            result = db.bytes.get_cstring_at(address)
        except Exception as exc:
            return _error_from_exc(f"failed to read C string at {address:#x}", exc)

        if result is None:
            return _error(f"no C string available at {address:#x}")

        if isinstance(result, (bytes, bytearray)):
            value = result.decode("utf-8", errors="replace")
        else:
            value = str(result)

        return {
            "string": value,
        }

    def get_segments():
        try:
            items = []
            for seg in db.segments:
                items.append({
                    "name": str(db.segments.get_name(seg)),
                    "start": int(seg.start_ea),
                    "end": int(seg.end_ea),
                    "size": int(db.segments.get_size(seg)),
                    "permissions": int(seg.perm),
                    "class": str(db.segments.get_class(seg)),
                    "bitness": int(db.segments.get_bitness(seg)),
                })
        except Exception as exc:
            return _error_from_exc("failed to enumerate segments", exc)

        return {
            "segments": items,
        }

    def get_names():
        try:
            items = []
            for ea, name in db.names:
                demangled = db.names.demangle_name(name)
                display_name = str(demangled) if demangled else str(name)
                items.append({"address": int(ea), "name": display_name})
        except Exception as exc:
            return _error_from_exc("failed to enumerate names", exc)

        return {
            "names": items,
        }

    def get_name_at(address):
        try:
            result = db.names.get_at(address)
        except Exception as exc:
            return _error_from_exc(f"failed to read symbol name at {address:#x}", exc)

        if not result:
            return _error(f"no symbol name available at {address:#x}")

        return {
            "name": str(result),
        }

    def demangle_name(name):
        try:
            result = db.names.demangle_name(name)
        except Exception as exc:
            return _error_from_exc(f"failed to demangle name {name!r}", exc)

        return {
            "demangled_name": str(result) if result else str(name),
        }

    def get_imports():
        results = []
        db_imports_error = None

        if hasattr(db, "imports"):
            try:
                for imp in db.imports.get_all_imports():
                    results.append({
                        "address": int(imp.address),
                        "name": str(imp.name),
                        "module": str(imp.module_name),
                        "ordinal": int(imp.ordinal),
                    })
                return {
                    "imports": results,
                }
            except Exception as exc:
                db_imports_error = exc
                results = []

        try:
            import ida_nalt  # type: ignore
        except Exception as exc:
            if db_imports_error is not None:
                return _error(
                    "failed to enumerate imports via db.imports "
                    f"({type(db_imports_error).__name__}: {db_imports_error}) and ida_nalt fallback "
                    f"is unavailable ({type(exc).__name__}: {exc})"
                )
            return _error_from_exc("failed to import ida_nalt for import enumeration", exc)

        try:
            module_count = int(ida_nalt.get_import_module_qty())
        except Exception as exc:
            if db_imports_error is not None:
                return _error(
                    "failed to enumerate imports via db.imports "
                    f"({type(db_imports_error).__name__}: {db_imports_error}) and could not read "
                    f"ida_nalt import module count ({type(exc).__name__}: {exc})"
                )
            return _error_from_exc("failed to read import module count", exc)

        for module_index in range(module_count):
            module_name = ida_nalt.get_import_module_name(module_index)
            module_name_str = str(module_name) if module_name else ""

            def _collect(ea, name, ordinal, _module=module_name_str):
                results.append({
                    "address": int(ea),
                    "name": str(name) if name is not None else "",
                    "module": _module,
                    "ordinal": int(ordinal),
                })
                return True

            try:
                ida_nalt.enum_import_names(module_index, _collect)
            except Exception:
                continue

        return {
            "imports": results,
        }

    def get_entries():
        try:
            items = []
            for entry in db.entries:
                forwarder = None
                has_forwarder = getattr(entry, "has_forwarder", None)
                if callable(has_forwarder):
                    if bool(has_forwarder()):
                        forwarder = str(entry.forwarder_name)
                elif bool(has_forwarder):
                    forwarder = str(entry.forwarder_name)

                items.append({
                    "ordinal": int(entry.ordinal),
                    "address": int(entry.address),
                    "name": str(entry.name),
                    "forwarder": forwarder,
                })
        except Exception as exc:
            return _error_from_exc("failed to enumerate entries", exc)

        return {
            "entries": items,
        }

    def get_bytes_at(address, size):
        if size < 0:
            return _error(f"size must be non-negative (got {size})")

        if size == 0:
            return {
                "bytes": [],
            }

        try:
            data = db.bytes.get_bytes_at(address, size)
        except Exception as exc:
            return _error_from_exc(f"failed to read {size} bytes at {address:#x}", exc)

        if data is None:
            return _error(f"unable to read {size} bytes at {address:#x}")

        return {
            "bytes": [int(b) for b in data],
        }

    def find_bytes(pattern):
        if not pattern:
            return _error("pattern must contain at least one byte")

        for i, byte in enumerate(pattern):
            if not isinstance(byte, int):
                return _error(f"pattern[{i}] must be int, got {type(byte).__name__}")
            if byte < 0 or byte > 255:
                return _error(f"pattern[{i}] must be in range 0..255, got {byte}")

        try:
            hits = db.bytes.find_binary_sequence(bytes(pattern))
        except Exception as exc:
            return _error_from_exc("byte-pattern search failed", exc)

        return {
            "addresses": [int(ea) for ea in hits],
        }

    def get_disassembly_at(address):
        try:
            result = db.bytes.get_disassembly_at(address)
        except Exception as exc:
            return _error_from_exc(f"failed to fetch disassembly at {address:#x}", exc)

        if result is None:
            return _error(f"no disassembly available at {address:#x}")

        return {
            "disassembly": str(result),
        }

    def get_instruction_at(address):
        try:
            insn = db.instructions.get_at(address)
        except Exception as exc:
            return _error_from_exc(f"failed to fetch instruction at {address:#x}", exc)

        if insn is None:
            return _error(f"no instruction available at {address:#x}")

        try:
            item = {
                "address": int(insn.ea),
                "size": int(insn.size),
                "mnemonic": str(db.instructions.get_mnemonic(insn)),
                "disassembly": str(db.instructions.get_disassembly(insn)),
                "is_call": bool(db.instructions.is_call_instruction(insn)),
            }
        except Exception as exc:
            return _error_from_exc(f"failed to serialize instruction at {address:#x}", exc)

        return item

    def get_address_type(address):
        try:
            if not bool(db.is_valid_ea(address)):
                return {
                    "address_type": "invalid",
                }
        except Exception as exc:
            return _error_from_exc(f"failed to validate address {address:#x}", exc)

        try:
            if bool(db.bytes.is_code_at(address)):
                return {
                    "address_type": "code",
                }
        except Exception:
            pass

        try:
            if bool(db.bytes.is_data_at(address)):
                return {
                    "address_type": "data",
                }
        except Exception:
            pass

        try:
            if bool(db.bytes.is_unknown_at(address)):
                return {
                    "address_type": "unknown",
                }
        except Exception:
            pass

        return {
            "address_type": "unknown",
        }

    def get_comment_at(address):
        try:
            result = db.comments.get_at(address)
        except Exception as exc:
            return _error_from_exc(f"failed to read comment at {address:#x}", exc)

        if not result:
            return _error(f"no comment available at {address:#x}")

        return {
            "comment": str(result),
        }

    api: dict[str, Callable[..., Any]] = {
        "help": help,
        "get_database_metadata": get_database_metadata,
        "get_functions": get_functions,
        "get_function_by_name": get_function_by_name,
        "get_function_at": get_function_at,
        "get_function_disassembly_at": get_function_disassembly_at,
        "decompile_function_at": decompile_function_at,
        "get_function_callers": get_function_callers,
        "get_function_callees": get_function_callees,
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
    """Return a Markdown function table generated from API implementations and type aliases."""
    implementation_functions = _implementation_functions_for_reference()
    rows = _api_rows_from_implementation(implementation_functions)

    lines = [
        "## Function reference",
        "",
        "All functions return either the success payload shown below or `{error: str}`.",
        "Callers should check for the presence of the `error` key to detect failures.",
        "",
        "| Function | Returns | Description |",
        "|----------|---------|-------------|",
    ]

    for function_name, signature, description in rows:
        rendered_return = _function_success_return_shape(function_name, implementation_functions)
        lines.append(f"| `{signature}` | `{rendered_return}` | {description} |")

    return "\n".join(lines)

