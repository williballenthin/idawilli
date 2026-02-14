"""IDA Codemode API.

Portable analysis APIs for IDA Pro suitable for sandboxed code execution,
JSON-RPC exposure, and LLM tool use.

For fallible operations, the API follows three conventions:

- Read APIs return ``SuccessPayload | ApiError``. Success payloads do **not**
  include a status discriminator. Failures use ``{"error": "..."}``.
- Mutation APIs return ``None`` on success or ``{"error": "..."}`` on failure.
- Utility helper ``expect_ok`` returns the original success payload or ``None``
  when given ``ApiError``.

Use :func:`create_api_from_database` to build concrete callables bound to an
open ``ida_domain.Database``.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from types import NoneType, UnionType
from typing import Any, Callable, Literal, ParamSpec, TypeVar, Union, cast, get_args, get_origin, get_type_hints

from . import api_types


TYPE_STUBS_PATH = Path(api_types.__file__ or "").resolve()
"""Filesystem path of the authoritative stub module."""

TYPE_STUBS = TYPE_STUBS_PATH.read_text(encoding="utf-8")
"""Authoritative API stubs consumed by Monty type checking."""


FUNCTION_NAMES: list[str] = [
    "help",
    "expect_ok",
    "get_database_metadata",
    "get_functions",
    "get_function_by_name",
    "get_function_at",
    "get_function_disassembly_at",
    "decompile_function_at",
    "get_function_callers",
    "get_function_callees",
    "get_function_data_xrefs",
    "get_function_string_xrefs",
    "get_xrefs_to_at",
    "get_xrefs_from_at",
    "get_strings",
    "get_string_at",
    "get_segments",
    "get_segment_containing",
    "get_names",
    "get_name_at",
    "demangle_name",
    "get_imports",
    "get_entries",
    "get_bytes_at",
    "find_bytes",
    "get_disassembly_at",
    "get_address_type",
    "get_comment_at",
    "read_pointer",
    "get_bookmarks",
    "add_bookmark",
    "delete_bookmark",
    "set_name_at",
    "set_type_at",
    "set_comment_at",
    "set_repeatable_comment_at",
    "set_local_variable_name",
    "set_local_variable_type",
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

    if isinstance(annotation, TypeVar):
        return annotation.__name__

    if isinstance(annotation, type):
        return annotation.__name__

    return str(annotation)


def _render_declaration_signature(function_name: str, declaration: Callable[..., Any]) -> str:
    signature = inspect.signature(declaration)

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

    return f"{function_name}({', '.join(rendered_parameters)})"


def _function_success_return_shape(function_name: str) -> str:
    declaration = getattr(api_types, function_name)
    hints = get_type_hints(declaration, include_extras=True)
    return_annotation = hints.get("return", Any)
    return _render_type(return_annotation)


def _api_rows_from_declarations() -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []

    for function_name in FUNCTION_NAMES:
        declaration = getattr(api_types, function_name, None)
        if declaration is None or not callable(declaration):
            continue

        signature = _render_declaration_signature(function_name, declaration)
        doc = inspect.getdoc(declaration) or ""
        description = doc.strip().splitlines()[0] if doc.strip() else ""
        rows.append((function_name, signature, description))

    return rows


ASCII_PRINTABLE = set(
    b" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\t"
)


def read_ascii_string_at(buf: bytes, min_len: int = 4) -> bytes | None:
    """Extract ASCII string starting exactly at buffer position 0."""
    if not buf or buf[0] not in ASCII_PRINTABLE:
        return None
    end = 0
    for i, b in enumerate(buf):
        if b not in ASCII_PRINTABLE:
            end = i
            break
    else:
        end = len(buf)
    if end >= min_len:
        return buf[:end]
    return None


def read_utf16le_string_at(buf: bytes, min_len: int = 4) -> bytes | None:
    """Extract UTF-16LE string starting exactly at buffer position 0."""
    if len(buf) < 2:
        return None
    if buf[0] not in ASCII_PRINTABLE or buf[1] != 0:
        return None
    end = 0
    for i in range(0, len(buf) - 1, 2):
        if buf[i] not in ASCII_PRINTABLE or buf[i + 1] != 0:
            end = i
            break
    else:
        end = len(buf) if len(buf) % 2 == 0 else len(buf) - 1
    char_count = end // 2
    if char_count >= min_len:
        return buf[:end]
    return None


def read_string_at(buf: bytes, min_len: int = 4) -> bytes | None:
    """Extract string starting exactly at buffer position 0.

    Tries ASCII first, then UTF-16LE.
    """
    result = read_ascii_string_at(buf, min_len)
    if result is not None:
        return result
    return read_utf16le_string_at(buf, min_len)


_STRING_READ_SIZE = 1024

ApiParam = ParamSpec("ApiParam")
ApiReturn = TypeVar("ApiReturn")


def create_api_from_database(db: Any) -> api_types.ApiFunctions:
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
            comment_str = comment.comment if comment else ""
        except Exception:
            comment_str = ""

        try:
            from ida_domain.comments import CommentKind
            repeatable = db.comments.get_at(func.start_ea, CommentKind.REPEATABLE)
            repeatable_str = repeatable.comment if repeatable else ""
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

    def _with_top_level_error(
        function_name: str,
        fn: Callable[ApiParam, ApiReturn],
    ) -> Callable[ApiParam, ApiReturn | api_types.ApiError]:
        def wrapped(*args: ApiParam.args, **kwargs: ApiParam.kwargs) -> ApiReturn | api_types.ApiError:
            try:
                return fn(*args, **kwargs)
            except Exception as exc:
                return _error_from_exc(f"{function_name}: unexpected error", exc)

        return wrapped

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

    def help(api: str) -> api_types.HelpResult:
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

        payload: api_types.HelpOk = {
            "documentation": f"{rendered_signature} -> {rendered_return}\n\n{doc}",
        }
        return payload

    def expect_ok(result: object) -> object | None:
        if isinstance(result, dict):
            payload = cast(dict[str, object], result)
            error_value = payload.get("error")
            if isinstance(error_value, str):
                return None
        return result

    def get_database_metadata() -> api_types.GetDatabaseMetadataResult:
        try:
            payload: api_types.DatabaseMetadata = {
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
            return payload
        except Exception as exc:
            return _error_from_exc("failed to read database metadata", exc)

    def get_functions() -> api_types.GetFunctionsResult:
        try:
            payload: api_types.GetFunctionsOk = {
                "functions": [_serialize_function(func) for func in db.functions],
            }
            return payload
        except Exception as exc:
            return _error_from_exc("failed to enumerate functions", exc)

    def get_function_by_name(name: str) -> api_types.GetFunctionByNameResult:
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

    def get_function_at(address: int) -> api_types.GetFunctionAtResult:
        func, err = _lookup_function_start(address, context="function lookup")
        if err is not None:
            return err

        return _serialize_function(func)

    def get_function_disassembly_at(address: int) -> api_types.GetFunctionDisassemblyAtResult:
        func, err = _lookup_function_containing(address, context="function disassembly")
        if err is not None:
            return err

        try:
            disassembly = db.functions.get_disassembly(func)
        except Exception as exc:
            return _error_from_exc(f"failed to disassemble function at {address:#x}", exc)

        if disassembly is None:
            return _error(f"no disassembly available for function at {address:#x}")

        payload: api_types.GetFunctionDisassemblyAtOk = {
            "disassembly": [str(line) for line in disassembly],
        }
        return payload

    def decompile_function_at(address: int) -> api_types.DecompileFunctionAtResult:
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

        payload: api_types.DecompileFunctionAtOk = {
            "pseudocode": [str(line) for line in result],
        }
        return payload

    def get_function_callers(address: int) -> api_types.GetFunctionCallersResult:
        func, err = _lookup_function_containing(address, context="caller analysis")
        if err is not None:
            return err

        try:
            callers = db.functions.get_callers(func)
            items = [_serialize_function(caller) for caller in callers]
        except Exception as exc:
            return _error_from_exc(f"failed to enumerate callers for function at {address:#x}", exc)

        payload: api_types.GetFunctionCallersOk = {
            "callers": items,
        }
        return payload

    def get_function_callees(address: int) -> api_types.GetFunctionCalleesResult:
        func, err = _lookup_function_containing(address, context="callee analysis")
        if err is not None:
            return err

        try:
            callees = db.functions.get_callees(func)
            items = [_serialize_function(callee) for callee in callees]
        except Exception as exc:
            return _error_from_exc(f"failed to enumerate callees for function at {address:#x}", exc)

        payload: api_types.GetFunctionCalleesOk = {
            "callees": items,
        }
        return payload

    def get_function_data_xrefs(function_start: int) -> api_types.GetFunctionDataXrefsResult:
        func, err = _lookup_function_start(function_start, context="function data xref analysis")
        if err is not None:
            return err

        try:
            items = []
            flowchart = db.functions.get_flowchart(func)
            if flowchart is None:
                payload: api_types.GetFunctionDataXrefsOk = {"xrefs": []}
                return payload

            visited = set()
            for block in flowchart:
                ea = int(block.start_ea)
                end_ea = int(block.end_ea)

                while ea < end_ea:
                    if ea not in visited:
                        visited.add(ea)
                        try:
                            for xref in db.xrefs.from_ea(ea):
                                if not xref.is_call and not xref.is_jump:
                                    items.append({
                                        "from_address": int(ea),
                                        "to_address": int(xref.to_ea),
                                        "type": str(xref.type.name),
                                    })
                        except Exception:
                            pass

                    try:
                        insn = db.instructions.get_at(ea)
                        if insn is not None:
                            ea += int(insn.size)
                        else:
                            ea += 1
                    except Exception:
                        ea += 1
        except Exception as exc:
            return _error_from_exc(f"failed to enumerate data xrefs for function at {function_start:#x}", exc)

        payload: api_types.GetFunctionDataXrefsOk = {
            "xrefs": items,
        }
        return payload

    def get_function_string_xrefs(function_start: int) -> api_types.GetFunctionStringXrefsResult:
        func, err = _lookup_function_start(function_start, context="function string xref analysis")
        if err is not None:
            return err

        try:
            items = []
            flowchart = db.functions.get_flowchart(func)
            if flowchart is None:
                payload: api_types.GetFunctionStringXrefsOk = {"xrefs": []}
                return payload

            visited = set()
            for block in flowchart:
                ea = int(block.start_ea)
                end_ea = int(block.end_ea)

                while ea < end_ea:
                    if ea not in visited:
                        visited.add(ea)
                        try:
                            for xref in db.xrefs.from_ea(ea):
                                if not xref.is_call and not xref.is_jump:
                                    target_ea = int(xref.to_ea)
                                    try:
                                        data = db.bytes.get_bytes_at(target_ea, _STRING_READ_SIZE)
                                        if data is not None:
                                            raw = read_string_at(bytes(data))
                                            if raw is not None:
                                                try:
                                                    if read_ascii_string_at(bytes(data)) is not None:
                                                        string_value = raw.decode("ascii")
                                                    else:
                                                        string_value = raw.decode("utf-16-le")
                                                except Exception:
                                                    string_value = raw.decode("utf-8", errors="replace")

                                                items.append({
                                                    "from_address": int(ea),
                                                    "string_address": target_ea,
                                                    "string": string_value,
                                                })
                                    except Exception:
                                        pass
                        except Exception:
                            pass

                    try:
                        insn = db.instructions.get_at(ea)
                        if insn is not None:
                            ea += int(insn.size)
                        else:
                            ea += 1
                    except Exception:
                        ea += 1
        except Exception as exc:
            return _error_from_exc(f"failed to enumerate string xrefs for function at {function_start:#x}", exc)

        payload: api_types.GetFunctionStringXrefsOk = {
            "xrefs": items,
        }
        return payload

    def get_xrefs_to_at(address: int) -> api_types.GetXrefsToAtResult:
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

        payload: api_types.GetXrefsToAtOk = {
            "xrefs": items,
        }
        return payload

    def get_xrefs_from_at(address: int) -> api_types.GetXrefsFromAtResult:
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

        payload: api_types.GetXrefsFromAtOk = {
            "xrefs": items,
        }
        return payload

    def get_strings() -> api_types.GetStringsResult:
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

        payload: api_types.GetStringsOk = {
            "strings": items,
        }
        return payload

    def get_string_at(address: int) -> api_types.GetStringAtResult:
        try:
            data = db.bytes.get_bytes_at(address, _STRING_READ_SIZE)
        except Exception as exc:
            return _error_from_exc(f"failed to read bytes at {address:#x}", exc)

        if data is None:
            return _error(f"unable to read bytes at {address:#x}")

        raw = read_string_at(bytes(data))
        if raw is None:
            return _error(f"no string at {address:#x}")

        try:
            if read_ascii_string_at(bytes(data)) is not None:
                value = raw.decode("ascii")
            else:
                value = raw.decode("utf-16-le")
        except Exception:
            value = raw.decode("utf-8", errors="replace")

        payload: api_types.GetStringAtOk = {
            "string": value,
        }
        return payload

    def get_segments() -> api_types.GetSegmentsResult:
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

        payload: api_types.GetSegmentsOk = {
            "segments": items,
        }
        return payload

    def get_segment_containing(address: int) -> api_types.GetSegmentContainingResult:
        try:
            seg = db.segments.get_at(address)
        except Exception as exc:
            return _error_from_exc(f"failed to look up segment at {address:#x}", exc)

        if seg is None:
            return _error(f"no segment contains address {address:#x}")

        try:
            payload: api_types.SegmentInfo = {
                "name": str(db.segments.get_name(seg)),
                "start": int(seg.start_ea),
                "end": int(seg.end_ea),
                "size": int(db.segments.get_size(seg)),
                "permissions": int(seg.perm),
                "class": str(db.segments.get_class(seg)),
                "bitness": int(db.segments.get_bitness(seg)),
            }
            return payload
        except Exception as exc:
            return _error_from_exc(f"failed to serialize segment at {address:#x}", exc)

    def get_names() -> api_types.GetNamesResult:
        try:
            items = []
            for ea, name in db.names:
                demangled = db.names.demangle_name(name)
                display_name = str(demangled) if demangled else str(name)
                items.append({"address": int(ea), "name": display_name})
        except Exception as exc:
            return _error_from_exc("failed to enumerate names", exc)

        payload: api_types.GetNamesOk = {
            "names": items,
        }
        return payload

    def get_name_at(address: int) -> api_types.GetNameAtResult:
        try:
            result = db.names.get_at(address)
        except Exception as exc:
            return _error_from_exc(f"failed to read symbol name at {address:#x}", exc)

        if not result:
            return _error(f"no symbol name available at {address:#x}")

        payload: api_types.GetNameAtOk = {
            "name": str(result),
        }
        return payload

    def demangle_name(name: str) -> api_types.DemangleNameResult:
        try:
            result = db.names.demangle_name(name)
        except Exception as exc:
            return _error_from_exc(f"failed to demangle name {name!r}", exc)

        payload: api_types.DemangleNameOk = {
            "demangled_name": str(result) if result else str(name),
        }
        return payload

    def get_imports() -> api_types.GetImportsResult:
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
                payload: api_types.GetImportsOk = {
                    "imports": results,
                }
                return payload
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

        payload: api_types.GetImportsOk = {
            "imports": results,
        }
        return payload

    def get_entries() -> api_types.GetEntriesResult:
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

        payload: api_types.GetEntriesOk = {
            "entries": items,
        }
        return payload

    def get_bytes_at(address: int, size: int) -> api_types.GetBytesAtResult:
        if size < 0:
            return _error(f"size must be non-negative (got {size})")

        if size == 0:
            payload: api_types.GetBytesAtOk = {
                "bytes": [],
            }
            return payload

        try:
            data = db.bytes.get_bytes_at(address, size)
        except Exception as exc:
            return _error_from_exc(f"failed to read {size} bytes at {address:#x}", exc)

        if data is None:
            return _error(f"unable to read {size} bytes at {address:#x}")

        payload: api_types.GetBytesAtOk = {
            "bytes": [int(b) for b in data],
        }
        return payload

    def find_bytes(pattern: list[int]) -> api_types.FindBytesResult:
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

        payload: api_types.FindBytesOk = {
            "addresses": [int(ea) for ea in hits],
        }
        return payload

    def get_disassembly_at(address: int) -> api_types.GetDisassemblyAtResult:
        try:
            result = db.bytes.get_disassembly_at(address)
        except Exception as exc:
            return _error_from_exc(f"failed to fetch disassembly at {address:#x}", exc)

        if result is None:
            return _error(f"no disassembly available at {address:#x}")

        payload: api_types.GetDisassemblyAtOk = {
            "disassembly": str(result),
        }
        return payload

    def get_address_type(address: int) -> api_types.GetAddressTypeResult:
        try:
            if not bool(db.is_valid_ea(address)):
                payload: api_types.GetAddressTypeOk = {
                    "address_type": "invalid",
                }
                return payload
        except Exception as exc:
            return _error_from_exc(f"failed to validate address {address:#x}", exc)

        try:
            if bool(db.bytes.is_code_at(address)):
                payload: api_types.GetAddressTypeOk = {
                    "address_type": "code",
                }
                return payload
        except Exception:
            pass

        try:
            if bool(db.bytes.is_data_at(address)):
                payload: api_types.GetAddressTypeOk = {
                    "address_type": "data",
                }
                return payload
        except Exception:
            pass

        try:
            if bool(db.bytes.is_unknown_at(address)):
                payload: api_types.GetAddressTypeOk = {
                    "address_type": "unknown",
                }
                return payload
        except Exception:
            pass

        payload: api_types.GetAddressTypeOk = {
            "address_type": "unknown",
        }
        return payload

    def get_comment_at(address: int) -> api_types.GetCommentAtResult:
        try:
            result = db.comments.get_at(address)
        except Exception as exc:
            return _error_from_exc(f"failed to read comment at {address:#x}", exc)

        if not result:
            return _error(f"no comment available at {address:#x}")

        payload: api_types.GetCommentAtOk = {
            "comment": result.comment,
        }
        return payload

    def read_pointer(address: int) -> api_types.ReadPointerResult:
        try:
            bitness = int(db.bitness)
        except Exception as exc:
            return _error_from_exc("failed to read database bitness", exc)

        pointer_size = 8 if bitness == 64 else 4

        try:
            data = db.bytes.get_bytes_at(address, pointer_size)
        except Exception as exc:
            return _error_from_exc(f"failed to read {pointer_size} bytes at {address:#x}", exc)

        if data is None:
            return _error(f"unable to read {pointer_size} bytes at {address:#x}")

        if len(data) < pointer_size:
            return _error(f"insufficient bytes at {address:#x}: expected {pointer_size}, got {len(data)}")

        try:
            pointer = int.from_bytes(data, byteorder='little', signed=False)
        except Exception as exc:
            return _error_from_exc(f"failed to decode pointer at {address:#x}", exc)

        payload: api_types.ReadPointerOk = {
            "pointer": pointer,
        }
        return payload

    def get_bookmarks() -> api_types.GetBookmarksResult:
        try:
            import idc
            import ida_idaapi
        except Exception as exc:
            return _error_from_exc("failed to import IDA modules for bookmark access", exc)

        try:
            items = []
            max_slots = 1024
            for index in range(max_slots):
                try:
                    ea = idc.get_bookmark(index)
                    if ea is None or ea == ida_idaapi.BADADDR:
                        continue

                    desc = idc.get_bookmark_desc(index)
                    if desc is None:
                        desc = ""

                    items.append({
                        "index": int(index),
                        "address": int(ea),
                        "description": str(desc),
                    })
                except Exception:
                    continue
        except Exception as exc:
            return _error_from_exc("failed to enumerate bookmarks", exc)

        payload: api_types.GetBookmarksOk = {
            "bookmarks": items,
        }
        return payload

    def add_bookmark(address: int, description: str) -> api_types.AddBookmarkResult:
        try:
            import idc
            import ida_idaapi
        except Exception as exc:
            return _error_from_exc("failed to import IDA modules for bookmark creation", exc)

        try:
            free_slot = None
            max_slots = 1024
            for index in range(max_slots):
                try:
                    ea = idc.get_bookmark(index)
                    if ea is None or ea == ida_idaapi.BADADDR:
                        free_slot = index
                        break
                except Exception:
                    free_slot = index
                    break

            if free_slot is None:
                return _error("no free bookmark slots available")

            put_result = idc.put_bookmark(address, 0, 0, 0, free_slot, description)
            if isinstance(put_result, bool) and not put_result:
                return _error(f"failed to add bookmark at {address:#x}")
            if isinstance(put_result, int) and not isinstance(put_result, bool) and put_result == 0:
                return _error(f"failed to add bookmark at {address:#x}")
        except Exception as exc:
            return _error_from_exc(f"failed to add bookmark at {address:#x}", exc)

        return None

    def delete_bookmark(index: int) -> api_types.DeleteBookmarkResult:
        try:
            import idc
            import ida_idaapi
        except Exception as exc:
            return _error_from_exc("failed to import IDA modules for bookmark deletion", exc)

        try:
            ea = idc.get_bookmark(index)
            if ea is None or ea == ida_idaapi.BADADDR:
                return _error(f"no bookmark exists at index {index}")

            put_result = idc.put_bookmark(ida_idaapi.BADADDR, 0, 0, 0, index, "")
            if isinstance(put_result, bool) and not put_result:
                return _error(f"failed to delete bookmark at index {index}")
            if isinstance(put_result, int) and not isinstance(put_result, bool) and put_result == 0:
                return _error(f"failed to delete bookmark at index {index}")
        except Exception as exc:
            return _error_from_exc(f"failed to delete bookmark at index {index}", exc)

        return None

    def set_name_at(address: int, name: str) -> api_types.SetNameAtResult:
        try:
            result = db.names.set_name(address, name)
            if isinstance(result, bool) and not result:
                return _error(f"failed to set name at {address:#x}")
            if isinstance(result, int) and not isinstance(result, bool) and result == 0:
                return _error(f"failed to set name at {address:#x}")
        except Exception as exc:
            return _error_from_exc(f"failed to set name at {address:#x}", exc)
        return None

    def set_type_at(address: int, type: str) -> api_types.SetTypeAtResult:
        try:
            import ida_typeinf

            type_str = type
            name = db.names.get_at(address)
            if not name:
                name = f"sub_{address:X}"

            if not type_str.rstrip().endswith(';'):
                type_str = type_str + ';'

            if '(' in type_str and name not in type_str:
                type_str = type_str.replace('(', f' {name}(', 1)

            tif = ida_typeinf.tinfo_t()  # ty: ignore[missing-argument]
            parse_result = ida_typeinf.parse_decl(tif, None, type_str, 0)  # ty: ignore[invalid-argument-type]
            if not parse_result:
                return _error(f"failed to parse type declaration: {type_str}")

            apply_result = ida_typeinf.apply_tinfo(address, tif, ida_typeinf.TINFO_DEFINITE)
            if not apply_result:
                return _error(f"failed to apply type at {address:#x}")
        except Exception as exc:
            return _error_from_exc(f"failed to set type at {address:#x}", exc)
        return None

    def set_comment_at(address: int, comment: str) -> api_types.SetCommentAtResult:
        try:
            result = db.comments.set_at(address, comment)
            if isinstance(result, bool) and not result:
                return _error(f"failed to set comment at {address:#x}")
            if isinstance(result, int) and not isinstance(result, bool) and result == 0:
                return _error(f"failed to set comment at {address:#x}")
        except Exception as exc:
            return _error_from_exc(f"failed to set comment at {address:#x}", exc)
        return None

    def set_repeatable_comment_at(address: int, comment: str) -> api_types.SetRepeatableCommentAtResult:
        try:
            from ida_domain.comments import CommentKind

            result = db.comments.set_at(address, comment, CommentKind.REPEATABLE)
            if isinstance(result, bool) and not result:
                return _error(f"failed to set repeatable comment at {address:#x}")
            if isinstance(result, int) and not isinstance(result, bool) and result == 0:
                return _error(f"failed to set repeatable comment at {address:#x}")
        except Exception as exc:
            return _error_from_exc(f"failed to set repeatable comment at {address:#x}", exc)
        return None

    def set_local_variable_name(function_address: int, existing_name: str, new_name: str) -> api_types.SetLocalVariableNameResult:
        func, err = _lookup_function_start(function_address, context="local variable rename")
        if err is not None:
            return err

        try:
            import ida_hexrays
        except Exception as exc:
            return _error_from_exc("failed to import ida_hexrays (decompiler required)", exc)

        try:
            cfunc = ida_hexrays.decompile(function_address)
        except Exception as exc:
            return _error_from_exc(f"failed to decompile function at {function_address:#x}", exc)

        if cfunc is None:
            return _error(f"decompilation failed for function at {function_address:#x}")

        matching_vars = []
        for lvar in cfunc.lvars:
            if str(lvar.name) == existing_name:
                matching_vars.append(lvar)

        if len(matching_vars) == 0:
            return _error(f"no local variable named {existing_name!r} in function at {function_address:#x}")

        if len(matching_vars) > 1:
            return _error(f"multiple local variables named {existing_name!r} in function at {function_address:#x}")

        try:
            lvar = matching_vars[0]
            lvar.name = new_name
            save_result = cfunc.save_user_lvars()
            if isinstance(save_result, bool) and not save_result:
                return _error(f"failed to rename local variable {existing_name!r} at {function_address:#x}")
            if isinstance(save_result, int) and not isinstance(save_result, bool) and save_result == 0:
                return _error(f"failed to rename local variable {existing_name!r} at {function_address:#x}")
        except Exception as exc:
            return _error_from_exc(f"failed to rename local variable {existing_name!r} at {function_address:#x}", exc)

        return None

    def set_local_variable_type(function_address: int, existing_name: str, type: str) -> api_types.SetLocalVariableTypeResult:
        func, err = _lookup_function_start(function_address, context="local variable retype")
        if err is not None:
            return err

        try:
            import ida_hexrays
            import ida_typeinf
        except Exception as exc:
            return _error_from_exc("failed to import ida_hexrays/ida_typeinf (decompiler required)", exc)

        try:
            cfunc = ida_hexrays.decompile(function_address)
        except Exception as exc:
            return _error_from_exc(f"failed to decompile function at {function_address:#x}", exc)

        if cfunc is None:
            return _error(f"decompilation failed for function at {function_address:#x}")

        matching_vars = []
        for lvar in cfunc.lvars:
            if str(lvar.name) == existing_name:
                matching_vars.append(lvar)

        if len(matching_vars) == 0:
            return _error(f"no local variable named {existing_name!r} in function at {function_address:#x}")

        if len(matching_vars) > 1:
            return _error(f"multiple local variables named {existing_name!r} in function at {function_address:#x}")

        try:
            type_str = type
            tinfo = ida_typeinf.tinfo_t()  # ty: ignore[missing-argument]
            if not ida_typeinf.parse_decl(tinfo, None, type_str, ida_typeinf.PT_SIL):  # ty: ignore[invalid-argument-type]
                return _error(f"failed to parse type string {type_str!r}")

            lvar = matching_vars[0]
            set_result = lvar.set_lvar_type(tinfo)
            if isinstance(set_result, bool) and not set_result:
                return _error(f"failed to set type for local variable {existing_name!r} at {function_address:#x}")
            if isinstance(set_result, int) and not isinstance(set_result, bool) and set_result == 0:
                return _error(f"failed to set type for local variable {existing_name!r} at {function_address:#x}")

            save_result = cfunc.save_user_lvars()
            if isinstance(save_result, bool) and not save_result:
                return _error(f"failed to persist local variable type for {existing_name!r} at {function_address:#x}")
            if isinstance(save_result, int) and not isinstance(save_result, bool) and save_result == 0:
                return _error(f"failed to persist local variable type for {existing_name!r} at {function_address:#x}")
        except Exception as exc:
            return _error_from_exc(f"failed to set type for local variable {existing_name!r} at {function_address:#x}", exc)

        return None

    api: api_types.ApiFunctions = {
        "help": _with_top_level_error("help", help),
        "expect_ok": _with_top_level_error("expect_ok", expect_ok),
        "get_database_metadata": _with_top_level_error("get_database_metadata", get_database_metadata),
        "get_functions": _with_top_level_error("get_functions", get_functions),
        "get_function_by_name": _with_top_level_error("get_function_by_name", get_function_by_name),
        "get_function_at": _with_top_level_error("get_function_at", get_function_at),
        "get_function_disassembly_at": _with_top_level_error("get_function_disassembly_at", get_function_disassembly_at),
        "decompile_function_at": _with_top_level_error("decompile_function_at", decompile_function_at),
        "get_function_callers": _with_top_level_error("get_function_callers", get_function_callers),
        "get_function_callees": _with_top_level_error("get_function_callees", get_function_callees),
        "get_function_data_xrefs": _with_top_level_error("get_function_data_xrefs", get_function_data_xrefs),
        "get_function_string_xrefs": _with_top_level_error("get_function_string_xrefs", get_function_string_xrefs),
        "get_xrefs_to_at": _with_top_level_error("get_xrefs_to_at", get_xrefs_to_at),
        "get_xrefs_from_at": _with_top_level_error("get_xrefs_from_at", get_xrefs_from_at),
        "get_strings": _with_top_level_error("get_strings", get_strings),
        "get_string_at": _with_top_level_error("get_string_at", get_string_at),
        "get_segments": _with_top_level_error("get_segments", get_segments),
        "get_segment_containing": _with_top_level_error("get_segment_containing", get_segment_containing),
        "get_names": _with_top_level_error("get_names", get_names),
        "get_name_at": _with_top_level_error("get_name_at", get_name_at),
        "demangle_name": _with_top_level_error("demangle_name", demangle_name),
        "get_imports": _with_top_level_error("get_imports", get_imports),
        "get_entries": _with_top_level_error("get_entries", get_entries),
        "get_bytes_at": _with_top_level_error("get_bytes_at", get_bytes_at),
        "find_bytes": _with_top_level_error("find_bytes", find_bytes),
        "get_disassembly_at": _with_top_level_error("get_disassembly_at", get_disassembly_at),
        "get_address_type": _with_top_level_error("get_address_type", get_address_type),
        "get_comment_at": _with_top_level_error("get_comment_at", get_comment_at),
        "read_pointer": _with_top_level_error("read_pointer", read_pointer),
        "get_bookmarks": _with_top_level_error("get_bookmarks", get_bookmarks),
        "add_bookmark": _with_top_level_error("add_bookmark", add_bookmark),
        "delete_bookmark": _with_top_level_error("delete_bookmark", delete_bookmark),
        "set_name_at": _with_top_level_error("set_name_at", set_name_at),
        "set_type_at": _with_top_level_error("set_type_at", set_type_at),
        "set_comment_at": _with_top_level_error("set_comment_at", set_comment_at),
        "set_repeatable_comment_at": _with_top_level_error("set_repeatable_comment_at", set_repeatable_comment_at),
        "set_local_variable_name": _with_top_level_error("set_local_variable_name", set_local_variable_name),
        "set_local_variable_type": _with_top_level_error("set_local_variable_type", set_local_variable_type),
    }

    return api


def api_reference() -> str:
    """Return a Markdown function table generated from API declarations and type aliases."""
    rows = _api_rows_from_declarations()

    lines = [
        "## Function reference",
        "",
        "Read functions return the success payload shown below or `{error: str}` on failure.",
        "Mutation functions return `None` on success or `{error: str}` on failure.",
        "Utility helper `expect_ok(result)` returns the original success payload or `None` for ApiError.",
        "For likely-success reads, prefer `expect_ok(...)`; branch on `None` before field access.",
        "",
        "| Function | Returns | Description |",
        "|----------|---------|-------------|",
    ]

    for function_name, signature, description in rows:
        rendered_return = _function_success_return_shape(function_name)
        lines.append(f"| `{signature}` | `{rendered_return}` | {description} |")

    return "\n".join(lines)

