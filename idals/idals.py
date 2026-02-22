#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "idapro",
#     "ida-domain",
#     "rich",
# ]
# ///

from __future__ import annotations

import argparse
import contextlib
import difflib
import hashlib
import importlib
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

from rich.console import Console
from rich.padding import Padding
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

__version__ = "0.1.0.dev0"
CACHE_DIR = Path.home() / ".cache" / "hex-rays" / "idals"
MAX_EXPORTS = 50
MAX_IMPORTS = 50
MAX_PSEUDOCODE_LINES = 64
MAX_XREFS = 100
MAX_XREFS_INLINE = 10
NOTABLE_IMPORTS = (
    "VirtualAlloc",
    "VirtualProtect",
    "VirtualFree",
    "CreateProcessA",
    "CreateProcessW",
    "CreateRemoteThread",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "InternetOpenUrlA",
    "InternetOpenUrlW",
    "WinHttpOpen",
    "WinHttpSendRequest",
    "RegOpenKeyA",
    "RegOpenKeyW",
    "RegSetValueA",
    "RegSetValueW",
    "NtCreateThread",
    "NtCreateThreadEx",
)
HEX_ADDRESS_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]+$")
LISTING_PREFIX_RE = re.compile(r"^[^:]+:[0-9A-Fa-f]{8,16}\s*")
INLINE_CODE_RE = re.compile(r"`([^`]+)`")
LABEL_PREFIX_RE = re.compile(r"^([A-Za-z_.$?@][\w.$?@]*:)(.*)$")
ASSIGN_PREFIX_RE = re.compile(r"^([A-Za-z_.$?@][\w.$?@]*)(\s*=.*)$")
NAME_PREFIX_RE = re.compile(r"^([A-Za-z_.$?@][\w.$?@]*)(\s+.*)$")
SIGNATURE_COMMENT_RE = re.compile(r"^;\s*.*__(?:cdecl|stdcall|fastcall|thiscall|vectorcall|usercall)\b.*\(.*\)")


class UsageError(Exception):
    """Raised when CLI arguments are invalid.
    """


class AddressError(Exception):
    """Raised when an address or symbol cannot be resolved.
    """


class AnalysisError(Exception):
    """Raised when IDA cannot open, analyze, or save a database.
    """


@dataclass
class XrefInfo:
    from_addr: int
    from_func_name: str | None
    from_func_ea: int | None
    xref_type: int


@dataclass
class FunctionContext:
    start_ea: int
    end_ea: int
    name: str
    is_func_start: bool
    signature: str | None
    comment: str | None
    xrefs_to: list[XrefInfo]
    instruction_count: int


@dataclass
class SegmentInfo:
    name: str
    start_ea: int
    end_ea: int
    permissions: str


@dataclass
class ImportInfo:
    name: str
    module: str
    ea: int


@dataclass
class ExportInfo:
    name: str
    ea: int
    ordinal: int


@dataclass
class ListingLine:
    ea: int
    tagged_line: str
    anterior_lines: list[str]
    posterior_lines: list[str]


@dataclass
class TipSuggestion:
    description: str
    command: str | None = None


@dataclass
class IdaRuntime:
    idapro: Any
    ida_auto: Any
    ida_lines: Any
    ida_funcs: Any
    ida_segment: Any
    ida_entry: Any
    ida_name: Any
    ida_bytes: Any
    ida_nalt: Any
    ida_xref: Any
    ida_hexrays: Any | None
    ida_ida: Any
    ida_loader: Any
    ida_idaapi: Any
    ida_typeinf: Any
    idautils: Any


_NAME_CACHE: list[tuple[int, str]] | None = None


def print_help_and_tutorial(use_rich: bool) -> None:
    """Print the self-contained usage tutorial.
    """
    if not use_rich:
        help_text = """idals — IDA Pro-powered binary inspection from the command line

USAGE
  idals <file>                                  Show binary overview (segments, entry points, imports)
  idals <file> <address>                        Show disassembly at address (--after defaults to 16)
  idals <file> <symbol>                         Show disassembly at named symbol
  idals <file> <address> --after N              Show N instructions/items after address
  idals <file> <address> --before N             Show N instructions/items before address
  idals <file> <address> --after N --before M   Show context around address

ADDRESS FORMATS
  0x140001000                       Hex with prefix
  140001000                         Bare hex
  main                              Symbol name
  CreateFileW                       Import name
  sub_140001000                     Auto-generated function name

OPTIONS
  --after N, -A          Instructions/items after target (default: 16)
  --before N, -B         Instructions/items before target (default: 0)
  --offsets va|rva|file  Address display mode (default: va)
  --decompile            Force pseudocode output regardless of length
  --no-decompile         Suppress pseudocode output entirely
  --no-color             Disable syntax highlighting
  -h, --help             Show this help tutorial
  -v, --version          Show version information

EXAMPLES
  $ idals suspicious.exe
  $ idals suspicious.exe 0x140001000
  $ idals suspicious.exe main
  $ idals suspicious.exe sub_140001000 --after 128
  $ idals suspicious.exe 0x14000BEEF --after 8 --before 8
  $ idals suspicious.exe 0x140001000 --offsets file

COMMON MISTAKES
  $ idals file.exe 1234
    If you mean decimal, convert to hex first.

  $ idals file.exe 0xDEAD
    If unmapped, run `idals file.exe` to inspect valid ranges.

TIPS
  • Start with `idals <file>` to discover entry points and imports.
  • Follow xrefs and named symbols to traverse behavior quickly.
  • Pipe to grep: `idals file.exe main --after 128 | grep -i call`
  • Pipe to less: `idals file.exe main --after 128 | less -R`
  • Cache location: ~/.cache/hex-rays/idals/
"""
        print(help_text)
        return

    console = Console(
        file=sys.stdout,
        force_terminal=True,
        markup=False,
        highlight=False,
    )
    section_style = "yellow"
    key_style = "bright_blue"
    muted_style = "grey58"

    def output_section(
        title: str,
        rows: list[tuple[str, str]],
        left_style: str | None = None,
    ) -> None:
        console.rule(Text(title, style=section_style), style=muted_style)
        table = Table.grid(padding=(0, 2))
        if left_style:
            table.add_column(style=left_style, no_wrap=True)
        else:
            table.add_column(no_wrap=True)
        table.add_column()
        for left, right in rows:
            table.add_row(left, right)
        console.print(table)
        console.print()

    console.print(
        Text(
            "idals — IDA Pro-powered binary inspection from the command line",
            style=key_style,
        )
    )
    console.print()

    output_section(
        "USAGE",
        [
            ("idals <file>", "Show binary overview (segments, entry points, imports)"),
            (
                "idals <file> <address>",
                "Show disassembly at address (--after defaults to 16)",
            ),
            ("idals <file> <symbol>", "Show disassembly at named symbol"),
            (
                "idals <file> <address> --after N",
                "Show N instructions/items after address",
            ),
            (
                "idals <file> <address> --before N",
                "Show N instructions/items before address",
            ),
            (
                "idals <file> <address> --after N --before M",
                "Show context around address",
            ),
        ],
    )

    output_section(
        "ADDRESS FORMATS",
        [
            ("0x140001000", "Hex with prefix"),
            ("140001000", "Bare hex"),
            ("main", "Symbol name"),
            ("CreateFileW", "Import name"),
            ("sub_140001000", "Auto-generated function name"),
        ],
    )

    output_section(
        "OPTIONS",
        [
            ("--after N, -A", "Instructions/items after target (default: 16)"),
            ("--before N, -B", "Instructions/items before target (default: 0)"),
            ("--offsets va|rva|file", "Address display mode (default: va)"),
            ("--decompile", "Force pseudocode output regardless of length"),
            ("--no-decompile", "Suppress pseudocode output entirely"),
            ("--no-color", "Disable syntax highlighting"),
            ("-h, --help", "Show this help tutorial"),
            ("-v, --version", "Show version information"),
        ],
        left_style=key_style,
    )

    console.rule(Text("EXAMPLES", style=section_style), style=muted_style)
    output_command_block(
        console,
        use_rich=True,
        commands=[
            "idals suspicious.exe",
            "idals suspicious.exe 0x140001000",
            "idals suspicious.exe main",
            "idals suspicious.exe sub_140001000 --after 128",
            "idals suspicious.exe 0x14000BEEF --after 8 --before 8",
            "idals suspicious.exe 0x140001000 --offsets file",
        ],
        indent=2,
    )
    console.print()

    console.rule(Text("COMMON MISTAKES", style=section_style), style=muted_style)
    console.print(Text("Wrong: passing a decimal value.", style=key_style))
    output_command_example(console, use_rich=True, command="idals file.exe 1234", indent=2)
    console.print("  If you mean decimal, convert to hex first.")
    console.print()
    console.print(Text("Wrong: address outside mapped segments.", style=key_style))
    output_command_example(console, use_rich=True, command="idals file.exe 0xDEAD", indent=2)
    console.print("  If unmapped, run `idals file.exe` to inspect valid ranges.")
    console.print()

    help_tips = [
        TipSuggestion(
            "Start with this to discover entry points and imports.",
            "idals <file>",
        ),
        TipSuggestion("Follow xrefs and named symbols to traverse behavior quickly."),
        TipSuggestion(
            "Search for call instructions in a larger window.",
            "idals file.exe main --after 128 | grep -i call",
        ),
        TipSuggestion(
            "Browse output with paging while preserving color.",
            "idals file.exe main --after 128 | less -R",
        ),
        TipSuggestion("Cache location: ~/.cache/hex-rays/idals/"),
    ]
    output_tips_section(
        console,
        use_rich=True,
        tips=help_tips,
        title_style=section_style,
        rule_style=muted_style,
    )


def build_argument_parser() -> argparse.ArgumentParser:
    """Build the CLI parser.
    """
    parser = argparse.ArgumentParser(prog="idals", add_help=False)
    parser.add_argument("file", nargs="?")
    parser.add_argument("address", nargs="?")
    parser.add_argument("-A", "--after", type=int, default=16)
    parser.add_argument("-B", "--before", type=int, default=0)
    parser.add_argument("--offsets", choices=["va", "rva", "file"], default="va")
    parser.add_argument("--decompile", action="store_true")
    parser.add_argument("--no-decompile", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("-v", "--version", action="store_true")
    return parser


def load_ida_runtime() -> IdaRuntime:
    """Load IDA modules lazily.

    Raises:
        AnalysisError: If one or more IDA modules cannot be imported.

    """

    def load_module(name: str) -> Any:
        try:
            return importlib.import_module(name)
        except Exception as exc:
            raise AnalysisError(f"Failed to import {name}: {exc}") from exc

    idapro = load_module("idapro")
    ida_auto = load_module("ida_auto")
    ida_lines = load_module("ida_lines")
    ida_funcs = load_module("ida_funcs")
    ida_segment = load_module("ida_segment")
    ida_entry = load_module("ida_entry")
    ida_name = load_module("ida_name")
    ida_bytes = load_module("ida_bytes")
    ida_nalt = load_module("ida_nalt")
    ida_xref = load_module("ida_xref")
    ida_ida = load_module("ida_ida")
    ida_loader = load_module("ida_loader")
    ida_idaapi = load_module("ida_idaapi")
    ida_typeinf = load_module("ida_typeinf")
    idautils = load_module("idautils")
    ida_hexrays: Any | None = None
    try:
        ida_hexrays = importlib.import_module("ida_hexrays")
    except Exception:
        ida_hexrays = None

    return IdaRuntime(
        idapro=idapro,
        ida_auto=ida_auto,
        ida_lines=ida_lines,
        ida_funcs=ida_funcs,
        ida_segment=ida_segment,
        ida_entry=ida_entry,
        ida_name=ida_name,
        ida_bytes=ida_bytes,
        ida_nalt=ida_nalt,
        ida_xref=ida_xref,
        ida_hexrays=ida_hexrays,
        ida_ida=ida_ida,
        ida_loader=ida_loader,
        ida_idaapi=ida_idaapi,
        ida_typeinf=ida_typeinf,
        idautils=idautils,
    )


def call_open_database(runtime: IdaRuntime, path: Path, auto_analysis: bool, new_database: bool) -> None:
    """Open an IDA database or binary using best-effort signature matching.

    Raises:
        AnalysisError: If opening fails.

    """
    load_args = "-R" if new_database else None
    attempts: list[Callable[[], Any]] = [
        lambda: runtime.idapro.open_database(str(path), auto_analysis, load_args, False),
        lambda: runtime.idapro.open_database(
            file_name=str(path), run_auto_analysis=auto_analysis, args=load_args, enable_history=False
        ),
        lambda: runtime.idapro.open_database(str(path), auto_analysis, load_args),
        lambda: runtime.idapro.open_database(str(path), auto_analysis),
        lambda: runtime.idapro.open_database(
            file_name=str(path), run_auto_analysis=auto_analysis
        ),
        lambda: runtime.idapro.open_database(str(path), auto_analysis, None, False),
        lambda: runtime.idapro.open_database(str(path)),
    ]
    last_type_error: Exception | None = None
    for attempt in attempts:
        try:
            attempt()
            return
        except TypeError as exc:
            last_type_error = exc
            continue
        except Exception as exc:
            raise AnalysisError(f"Failed to open {path}: {exc}") from exc
    raise AnalysisError(f"Failed to open {path}: incompatible API ({last_type_error})")


def call_save_database(runtime: IdaRuntime, path: Path) -> None:
    """Save current IDA database.

    Raises:
        AnalysisError: If saving fails.

    """
    attempts: list[Callable[[], Any]] = [
        lambda: runtime.ida_loader.save_database(str(path), 0),
        lambda: runtime.ida_loader.save_database(str(path)),
    ]

    with contextlib.suppress(Exception):
        idc = importlib.import_module("idc")
        attempts.extend(
            [
                lambda: idc.save_database(str(path), 0),
                lambda: idc.save_database(str(path)),
            ]
        )

    last_type_error: Exception | None = None
    for attempt in attempts:
        try:
            result = attempt()
            if result is False:
                continue
            return
        except TypeError as exc:
            last_type_error = exc
            continue
        except Exception as exc:
            raise AnalysisError(f"Failed to save database to {path}: {exc}") from exc
    raise AnalysisError(f"Failed to save database to {path}: incompatible API ({last_type_error})")


def call_close_database(runtime: IdaRuntime) -> None:
    """Close currently open IDA database.
    """
    close_fn = getattr(runtime.idapro, "close_database", None)
    if callable(close_fn):
        for args in ((False,), tuple()):
            with contextlib.suppress(Exception):
                close_fn(*args)
                return


def compute_file_hashes(file_path: Path) -> tuple[str, str]:
    """Compute (md5, sha256) for a file.

    Raises:
        OSError: If the file cannot be read.

    """
    md5_digest = hashlib.md5()
    sha256_digest = hashlib.sha256()
    with file_path.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(65536), b""):
            md5_digest.update(chunk)
            sha256_digest.update(chunk)
    return md5_digest.hexdigest(), sha256_digest.hexdigest()


def resolve_database(file_path: Path, stderr_console: Console) -> Path:
    """Resolve an input path to an .i64/.idb database path.

    Raises:
        AnalysisError: If analysis or caching fails.

    """
    suffix = file_path.suffix.lower()
    if suffix in {".i64", ".idb"}:
        return file_path

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    _, file_sha256 = compute_file_hashes(file_path)
    cache_path = CACHE_DIR / f"{file_sha256}.i64"
    if cache_path.exists():
        return cache_path

    stderr_console.print(f"Analyzing {file_path.name} (this may take a moment)...")
    runtime = load_ida_runtime()
    try:
        call_open_database(runtime, file_path, auto_analysis=True, new_database=True)
        runtime.ida_auto.auto_wait()
        call_save_database(runtime, cache_path)
    except Exception as exc:
        raise AnalysisError(f"Analysis failed for {file_path}: {exc}") from exc
    finally:
        call_close_database(runtime)
    return cache_path


@contextlib.contextmanager
def open_database_session(db_path: Path, auto_analysis: bool = False) -> Iterator[IdaRuntime]:
    """Open and close a database session.

    Raises:
        AnalysisError: If opening fails.

    """
    runtime = load_ida_runtime()
    call_open_database(runtime, db_path, auto_analysis=auto_analysis, new_database=False)
    if auto_analysis:
        runtime.ida_auto.auto_wait()
    try:
        yield runtime
    finally:
        call_close_database(runtime)


def get_permissions_string(runtime: IdaRuntime, perm: int) -> str:
    """Format segment permissions as rwx triplet.
    """
    read_mask = int(getattr(runtime.ida_segment, "SEGPERM_READ", 4))
    write_mask = int(getattr(runtime.ida_segment, "SEGPERM_WRITE", 2))
    exec_mask = int(getattr(runtime.ida_segment, "SEGPERM_EXEC", 1))
    return f"{'r' if perm & read_mask else '-'}{'w' if perm & write_mask else '-'}{'x' if perm & exec_mask else '-'}"


def get_segment_infos(runtime: IdaRuntime) -> list[SegmentInfo]:
    """Collect segment information.
    """
    segments: list[SegmentInfo] = []
    quantity = runtime.ida_segment.get_segm_qty()
    for index in range(quantity):
        segment = runtime.ida_segment.getnseg(index)
        if segment is None:
            continue
        name = runtime.ida_segment.get_segm_name(segment) or f"seg_{index}"
        segments.append(
            SegmentInfo(
                name=name,
                start_ea=int(segment.start_ea),
                end_ea=int(segment.end_ea),
                permissions=get_permissions_string(runtime, int(segment.perm)),
            )
        )
    return segments


def get_export_infos(runtime: IdaRuntime) -> list[ExportInfo]:
    """Collect entry records from IDA's entry table.
    """
    exports: list[ExportInfo] = []
    quantity = runtime.ida_entry.get_entry_qty()
    for index in range(quantity):
        ordinal = int(runtime.ida_entry.get_entry_ordinal(index))
        ea = int(runtime.ida_entry.get_entry(ordinal))
        if ea == runtime.ida_idaapi.BADADDR:
            continue
        name = runtime.ida_entry.get_entry_name(ordinal) or runtime.ida_name.get_name(ea) or f"ord_{ordinal}"
        exports.append(ExportInfo(name=name, ea=ea, ordinal=ordinal))
    exports.sort(key=lambda entry: (entry.ea, entry.ordinal, entry.name.lower()))
    return exports


def split_dll_exports(entry_infos: list[ExportInfo]) -> list[ExportInfo]:
    """Extract export entries from IDA's mixed entry table.
    """
    exports: list[ExportInfo] = []
    for entry in entry_infos:
        if entry.ordinal == entry.ea:
            continue
        exports.append(entry)
    return exports


def parse_pe_characteristics(path: Path) -> int | None:
    """Parse PE COFF characteristics from a file.
    """
    try:
        with path.open("rb") as file_handle:
            mz_header = file_handle.read(64)
            if len(mz_header) < 64 or mz_header[:2] != b"MZ":
                return None
            pe_offset = int.from_bytes(mz_header[0x3C:0x40], "little")
            file_handle.seek(pe_offset)
            if file_handle.read(4) != b"PE\x00\x00":
                return None
            coff_header = file_handle.read(20)
            if len(coff_header) < 20:
                return None
            return int.from_bytes(coff_header[18:20], "little")
    except OSError:
        return None


def is_dll_binary(runtime: IdaRuntime, file_path: Path, dll_exports: list[ExportInfo]) -> bool:
    """Determine whether the analyzed input is a DLL.
    """
    if file_path.suffix.lower() == ".dll":
        return True

    characteristics = parse_pe_characteristics(file_path)
    if characteristics is not None:
        return bool(characteristics & 0x2000)

    get_root_filename = getattr(runtime.ida_nalt, "get_root_filename", None)
    if callable(get_root_filename):
        root_filename = str(get_root_filename() or "")
        if root_filename.lower().endswith(".dll"):
            return True

    return bool(dll_exports)


def get_import_infos(runtime: IdaRuntime) -> tuple[dict[str, list[ImportInfo]], int]:
    """Collect imported symbols grouped by module.
    """
    imports: list[ImportInfo] = []
    module_quantity = runtime.ida_nalt.get_import_module_qty()
    for index in range(module_quantity):
        module_name = runtime.ida_nalt.get_import_module_name(index) or f"module_{index}"

        def callback(ea: int, name: str | None, ordinal: int, module: str = module_name) -> bool:
            import_name = name or f"ord_{ordinal}"
            imports.append(ImportInfo(name=import_name, module=module, ea=int(ea)))
            return True

        runtime.ida_nalt.enum_import_names(index, callback)

    imports.sort(key=lambda item: (item.module.lower(), item.name.lower(), item.ea))
    total = len(imports)
    visible = imports[:MAX_IMPORTS]
    grouped: dict[str, list[ImportInfo]] = {}
    for item in visible:
        grouped.setdefault(item.module, []).append(item)
    return grouped, total


def get_function_counts(runtime: IdaRuntime) -> tuple[int, int]:
    """Return (total functions, named functions).
    """
    total = 0
    named = 0
    for ea in runtime.idautils.Functions():
        total += 1
        func_name = runtime.ida_funcs.get_func_name(ea) or ""
        if not func_name.startswith("sub_"):
            named += 1
    return total, named


def get_sample_named_function(runtime: IdaRuntime) -> tuple[int, str] | None:
    """Pick one named function for tips.
    """
    for ea in runtime.idautils.Functions():
        name = runtime.ida_funcs.get_func_name(ea) or ""
        if name and not name.startswith("sub_"):
            return int(ea), name
    return None


def get_interesting_import(grouped_imports: dict[str, list[ImportInfo]]) -> ImportInfo | None:
    """Pick one notable import if available.
    """
    all_imports = [item for entries in grouped_imports.values() for item in entries]
    for notable in NOTABLE_IMPORTS:
        for item in all_imports:
            if item.name.lower() == notable.lower():
                return item
    return all_imports[0] if all_imports else None


def is_mapped_address(runtime: IdaRuntime, ea: int) -> bool:
    """Check whether address maps to a segment.
    """
    if ea == runtime.ida_idaapi.BADADDR:
        return False
    get_segment = getattr(runtime.ida_segment, "getseg", None)
    if callable(get_segment):
        return get_segment(ea) is not None
    min_ea = int(runtime.ida_ida.inf_get_min_ea())
    max_ea = int(runtime.ida_ida.inf_get_max_ea())
    return min_ea <= ea < max_ea


def get_name_cache(runtime: IdaRuntime) -> list[tuple[int, str]]:
    """Build and cache list of names for fuzzy matching.
    """
    global _NAME_CACHE
    if _NAME_CACHE is None:
        cache: list[tuple[int, str]] = []
        for ea, name in runtime.idautils.Names():
            if name:
                cache.append((int(ea), str(name)))
        _NAME_CACHE = cache
    return _NAME_CACHE


def build_unmapped_error(runtime: IdaRuntime, ea: int) -> str:
    """Create mapped-range error message.
    """
    lines = [
        f"Error: Address 0x{ea:X} is not mapped in the binary.",
        "Valid address ranges:",
    ]
    for segment in get_segment_infos(runtime):
        lines.append(f"  {segment.name} 0x{segment.start_ea:X} - 0x{segment.end_ea:X}")
    lines.append("Tip: Use `idals <file>` (no address) to see the full memory layout.")
    return "\n".join(lines)


def build_symbol_not_found_error(runtime: IdaRuntime, symbol: str) -> str:
    """Create symbol-not-found message with suggestions.
    """
    name_cache = get_name_cache(runtime)
    names = [name for _, name in name_cache]
    close = difflib.get_close_matches(symbol, names, n=5, cutoff=0.6)
    lines = [f"Error: Symbol \"{symbol}\" not found."]
    if close:
        lines.append("Did you mean:")
        by_name = {name: ea for ea, name in name_cache}
        for candidate in close:
            lines.append(f"  {candidate}@0x{by_name[candidate]:X}")
    lines.append("Tip: Use `idals <file>` to inspect available imports/exports and names.")
    return "\n".join(lines)


def resolve_address(runtime: IdaRuntime, address_str: str) -> int:
    """Resolve a user-provided address or symbol.

    Raises:
        AddressError: If the input cannot be resolved.

    """
    text = address_str.strip()

    if text.lower().startswith("0x"):
        try:
            ea = int(text, 16)
        except ValueError as exc:
            raise AddressError(f"Error: Invalid address: {text}") from exc
        if not is_mapped_address(runtime, ea):
            raise AddressError(build_unmapped_error(runtime, ea))
        return ea

    numeric_candidate: int | None = None
    if HEX_ADDRESS_RE.fullmatch(text):
        try:
            numeric_candidate = int(text, 16)
        except ValueError:
            numeric_candidate = None
        if numeric_candidate is not None and is_mapped_address(runtime, numeric_candidate):
            return numeric_candidate

    ea = int(runtime.ida_name.get_name_ea(runtime.ida_idaapi.BADADDR, text))
    if ea != runtime.ida_idaapi.BADADDR and is_mapped_address(runtime, ea):
        return ea

    if numeric_candidate is not None:
        raise AddressError(build_unmapped_error(runtime, numeric_candidate))
    raise AddressError(build_symbol_not_found_error(runtime, text))


def get_function_signature(runtime: IdaRuntime, func_ea: int) -> str | None:
    """Get a function signature string when available.
    """
    try:
        idc = importlib.import_module("idc")
        signature = idc.get_type(func_ea)
        if signature:
            return str(signature)
    except Exception:
        return None
    return None


def count_heads_in_range(runtime: IdaRuntime, start_ea: int, end_ea: int) -> int:
    """Count item heads in [start_ea, end_ea).
    """
    count = 0
    ea = start_ea
    bad = runtime.ida_idaapi.BADADDR
    while ea != bad and ea < end_ea:
        count += 1
        next_ea = runtime.ida_bytes.next_head(ea, end_ea)
        if next_ea == bad or next_ea <= ea:
            break
        ea = next_ea
    return count


def get_xrefs_to_function(runtime: IdaRuntime, func_ea: int) -> list[XrefInfo]:
    """Collect xrefs to a function, capped.
    """
    xrefs: list[XrefInfo] = []
    for xref in runtime.idautils.XrefsTo(func_ea, 0):
        if len(xrefs) >= MAX_XREFS:
            break
        caller_func = runtime.ida_funcs.get_func(xref.frm)
        caller_name: str | None = None
        caller_ea: int | None = None
        if caller_func is not None:
            caller_ea = int(caller_func.start_ea)
            caller_name = runtime.ida_funcs.get_func_name(caller_func.start_ea) or None
        xrefs.append(
            XrefInfo(
                from_addr=int(xref.frm),
                from_func_name=caller_name,
                from_func_ea=caller_ea,
                xref_type=int(xref.type),
            )
        )
    return xrefs


def get_function_context(runtime: IdaRuntime, ea: int) -> FunctionContext | None:
    """Find function context for address.
    """
    func = runtime.ida_funcs.get_func(ea)
    if func is None:
        return None

    start_ea = int(func.start_ea)
    end_ea = int(func.end_ea)
    name = runtime.ida_funcs.get_func_name(start_ea) or f"sub_{start_ea:X}"
    signature = get_function_signature(runtime, start_ea)
    comment = runtime.ida_funcs.get_func_cmt(func, False) or runtime.ida_funcs.get_func_cmt(func, True)
    xrefs = get_xrefs_to_function(runtime, start_ea)
    instruction_count = count_heads_in_range(runtime, start_ea, end_ea)

    return FunctionContext(
        start_ea=start_ea,
        end_ea=end_ea,
        name=name,
        is_func_start=(ea == start_ea),
        signature=signature,
        comment=comment,
        xrefs_to=xrefs,
        instruction_count=instruction_count,
    )


def generate_listing_heads(
    runtime: IdaRuntime,
    target_ea: int,
    before: int,
    after: int,
    func_ctx: FunctionContext | None,
) -> list[int]:
    """Get list of heads around target, with function-boundary clamping.
    """
    head = target_ea
    get_head = getattr(runtime.ida_bytes, "get_item_head", None)
    if callable(get_head):
        head = int(get_head(target_ea))

    min_ea = int(runtime.ida_ida.inf_get_min_ea())
    max_ea = int(runtime.ida_ida.inf_get_max_ea())
    lower_bound = func_ctx.start_ea if func_ctx else min_ea
    upper_bound = func_ctx.end_ea if func_ctx else max_ea

    bad = runtime.ida_idaapi.BADADDR
    before_heads: list[int] = []
    cursor = head
    for _ in range(before):
        previous = int(runtime.ida_bytes.prev_head(cursor, lower_bound))
        if previous == bad or previous < lower_bound:
            break
        before_heads.append(previous)
        cursor = previous
    before_heads.reverse()

    after_heads: list[int] = [head]
    cursor = head
    requested_after = max(after, 1)
    for _ in range(requested_after - 1):
        next_ea = int(runtime.ida_bytes.next_head(cursor, upper_bound))
        if next_ea == bad or next_ea >= upper_bound:
            break
        after_heads.append(next_ea)
        cursor = next_ea

    return before_heads + after_heads


def normalize_match_line(value: str) -> str:
    """Normalize listing lines for equality checks.
    """
    return " ".join(value.strip().split())


def strip_listing_prefix(line: str) -> str:
    """Remove the segment:address prefix from an IDA disassembly line.
    """
    return LISTING_PREFIX_RE.sub("", line, count=1)


def get_head_listing_lines(runtime: IdaRuntime, ea: int) -> list[str]:
    """Get all disassembly lines generated for a single head.
    """
    generate_disassembly = getattr(runtime.ida_lines, "generate_disassembly", None)
    if not callable(generate_disassembly):
        return []

    result: Any = None
    with contextlib.suppress(TypeError):
        result = generate_disassembly(ea, 256, True, True, True)
    if result is None:
        with contextlib.suppress(TypeError):
            result = generate_disassembly(ea, 256, True, True)
    if result is None:
        return []

    generated_lines: list[str] = []
    if isinstance(result, tuple) and len(result) >= 2 and isinstance(result[1], list):
        generated_lines = [str(line) for line in result[1]]
    elif isinstance(result, list):
        generated_lines = [str(line) for line in result]

    output_lines: list[str] = []
    for generated_line in generated_lines:
        cleaned_line = strip_listing_prefix(generated_line).rstrip()
        if cleaned_line:
            output_lines.append(cleaned_line)
    return output_lines


def get_extra_comment_lines(runtime: IdaRuntime, ea: int, where: int) -> list[str]:
    """Get IDA extra comment lines for a head.
    """
    get_extra_cmt = getattr(runtime.ida_lines, "get_extra_cmt", None)
    if not callable(get_extra_cmt):
        return []

    output_lines: list[str] = []
    for index in range(where, where + 256):
        value = get_extra_cmt(ea, index)
        if not value:
            break
        line = str(value).rstrip()
        if line:
            output_lines.append(line)
    return output_lines


def merge_unique_lines(primary: list[str], secondary: list[str]) -> list[str]:
    """Merge line lists while preserving order and removing duplicates.
    """
    seen = {normalize_match_line(line) for line in primary}
    merged = list(primary)
    for line in secondary:
        marker = normalize_match_line(line)
        if marker in seen:
            continue
        seen.add(marker)
        merged.append(line)
    return merged


def generate_listing_lines(runtime: IdaRuntime, heads: list[int]) -> list[ListingLine]:
    """Generate disassembly lines for heads.
    """
    lines: list[ListingLine] = []
    for ea in heads:
        text = runtime.ida_lines.generate_disasm_line(ea, 0)
        if not text:
            continue

        tagged_line = str(text)
        all_head_lines = get_head_listing_lines(runtime, ea)
        main_plain = strip_tagged_line(runtime, tagged_line)
        main_index: int | None = None
        normalized_main = normalize_match_line(main_plain)
        for index, line in enumerate(all_head_lines):
            if normalize_match_line(line) == normalized_main:
                main_index = index
        if main_index is None:
            main_index = len(all_head_lines) - 1

        if main_index >= 0:
            anterior_lines = all_head_lines[:main_index]
            posterior_lines = all_head_lines[main_index + 1 :]
        else:
            anterior_lines = []
            posterior_lines = []

        extra_pre = get_extra_comment_lines(runtime, ea, int(runtime.ida_lines.E_PREV))
        extra_post = get_extra_comment_lines(runtime, ea, int(runtime.ida_lines.E_NEXT))
        anterior_lines = merge_unique_lines(extra_pre, anterior_lines)
        posterior_lines = merge_unique_lines(posterior_lines, extra_post)

        lines.append(
            ListingLine(
                ea=ea,
                tagged_line=tagged_line,
                anterior_lines=anterior_lines,
                posterior_lines=posterior_lines,
            )
        )
    return lines


def get_last_function_line(runtime: IdaRuntime, func_ctx: FunctionContext) -> ListingLine | None:
    """Get the final instruction/data line in a function.
    """
    last_head = int(runtime.ida_bytes.prev_head(func_ctx.end_ea, func_ctx.start_ea))
    if last_head == runtime.ida_idaapi.BADADDR:
        return None
    lines = generate_listing_lines(runtime, [last_head])
    return lines[0] if lines else None


def get_xref_context(runtime: IdaRuntime, from_ea: int, offsets_mode: str) -> str:
    """Resolve the most useful xref context for a source address.
    """
    caller_func = runtime.ida_funcs.get_func(from_ea)
    if caller_func is not None:
        caller_ea = int(caller_func.start_ea)
        caller_name = runtime.ida_funcs.get_func_name(caller_ea)
        if caller_name:
            return format_symbol_ref(runtime, caller_name, caller_ea, offsets_mode)

    fallback_name = runtime.ida_name.get_name(from_ea)
    if fallback_name:
        return format_symbol_ref(runtime, fallback_name, from_ea, offsets_mode)

    return format_address(runtime, from_ea, offsets_mode)


def get_data_xref_annotations(runtime: IdaRuntime, ea: int, offsets_mode: str) -> list[str]:
    """Get data xrefs annotation lines for non-code items.
    """
    flags = runtime.ida_bytes.get_flags(ea)
    if runtime.ida_bytes.is_code(flags):
        return []

    refs: list[str] = []
    seen_from: set[int] = set()
    for xref in runtime.idautils.XrefsTo(ea, 0):
        from_ea = int(xref.frm)
        if from_ea in seen_from:
            continue
        seen_from.add(from_ea)

        refs.append(
            f"; XREF: {format_address(runtime, from_ea, offsets_mode)} "
            f"(in {get_xref_context(runtime, from_ea, offsets_mode)})"
        )

    if not refs:
        return []
    if len(refs) > MAX_XREFS_INLINE:
        return [f"; XREF: {len(refs)} references"]
    return refs


def get_pseudocode_lines(runtime: IdaRuntime, func_ea: int) -> list[str] | None:
    """Try to decompile a function.
    """
    ida_hexrays = runtime.ida_hexrays
    if ida_hexrays is None:
        return None

    try:
        if not ida_hexrays.init_hexrays_plugin():
            return None
    except Exception:
        return None

    func = runtime.ida_funcs.get_func(func_ea)
    if func is None or int(func.start_ea) != func_ea:
        return None

    decomp_failure = getattr(ida_hexrays, "DecompilationFailure", Exception)
    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except decomp_failure:
        return None
    except Exception:
        return None

    if cfunc is None:
        return None

    pseudocode = cfunc.get_pseudocode()
    lines: list[str] = []
    for source_line in pseudocode:
        line = getattr(source_line, "line", None)
        if line is None:
            continue
        lines.append(str(line))
    return lines if lines else None


def get_tag_code(value: Any, default: int) -> int:
    """Normalize IDA tag constants to int byte values.
    """
    if value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return ord(value[0])
    if isinstance(value, bytes):
        return int(value[0])
    return default


def get_tag_constants(runtime: IdaRuntime) -> tuple[int, int, int, int, int, int]:
    """Read tag marker constants from ida_lines.
    """
    ida_lines = runtime.ida_lines
    color_on = get_tag_code(getattr(ida_lines, "SCOLOR_ON", None), 0x01)
    color_off = get_tag_code(getattr(ida_lines, "SCOLOR_OFF", None), 0x02)
    color_esc = get_tag_code(getattr(ida_lines, "SCOLOR_ESC", None), 0x03)
    color_inv = get_tag_code(getattr(ida_lines, "SCOLOR_INV", None), 0x04)
    color_addr = get_tag_code(
        getattr(ida_lines, "SCOLOR_ADDR", getattr(ida_lines, "COLOR_ADDR", None)),
        0x05,
    )
    badaddr = int(runtime.ida_idaapi.BADADDR)
    address_len = 16 if badaddr > 0xFFFFFFFF else 8
    return color_on, color_off, color_esc, color_inv, color_addr, address_len


def get_style_code(ida_lines: Any, names: tuple[str, ...]) -> int | None:
    """Resolve first available color constant for a style mapping.
    """
    for name in names:
        if hasattr(ida_lines, name):
            return get_tag_code(getattr(ida_lines, name), -1)
    return None


def build_tag_style_map(runtime: IdaRuntime) -> dict[int, str]:
    """Build mapping from IDA color tags to rich styles.
    """
    ida_lines = runtime.ida_lines
    style_map: dict[int, str] = {}
    style_specs: list[tuple[tuple[str, ...], str]] = [
        (("SCOLOR_INSN", "COLOR_INSN"), "bold blue"),
        (("SCOLOR_REG", "COLOR_REG"), "cyan"),
        (("SCOLOR_NUMBER", "COLOR_NUMBER"), "bright_red"),
        (("SCOLOR_STRING", "COLOR_STRING"), "green"),
        (("SCOLOR_DNAME", "COLOR_DNAME"), "yellow"),
        (("SCOLOR_CNAME", "COLOR_CNAME"), "yellow"),
        (("SCOLOR_ASMDIR", "COLOR_ASMDIR"), "magenta"),
        (("SCOLOR_AUTOCMT", "COLOR_AUTOCMT"), "bright_black"),
        (("SCOLOR_REGCMT", "COLOR_REGCMT"), "bright_black"),
        (("SCOLOR_RPTCMT", "COLOR_RPTCMT"), "bright_black"),
        (("SCOLOR_SEGNAME", "COLOR_SEGNAME"), "magenta"),
        (("SCOLOR_ADDR", "COLOR_ADDR"), "bright_black"),
        (("SCOLOR_OPND1", "COLOR_OPND1"), "white"),
        (("SCOLOR_OPND2", "COLOR_OPND2"), "white"),
    ]
    for names, style in style_specs:
        code = get_style_code(ida_lines, names)
        if code is not None and code >= 0:
            style_map[code] = style
    return style_map


def skip_address_payload(tagged_line: str, index: int, address_len: int) -> int:
    """Skip encoded payload following a COLOR_ADDR marker.
    """
    max_len = min(len(tagged_line), index + max(address_len * 2, address_len))
    cursor = index
    while cursor < max_len and tagged_line[cursor] in "0123456789abcdefABCDEF":
        cursor += 1
    if cursor - index >= address_len:
        return cursor
    return min(len(tagged_line), index + address_len)


def line_has_tags(line: str) -> bool:
    """Check whether a line contains IDA color control bytes.
    """
    return any(token in line for token in ("\x01", "\x02", "\x03", "\x04"))


def strip_tagged_line(runtime: IdaRuntime, tagged_line: str) -> str:
    """Remove IDA tags from a line.
    """
    tag_remove = getattr(runtime.ida_lines, "tag_remove", None)
    if callable(tag_remove):
        return str(tag_remove(tagged_line))

    color_on, color_off, color_esc, color_inv, color_addr, address_len = get_tag_constants(runtime)
    output: list[str] = []
    index = 0
    while index < len(tagged_line):
        byte = ord(tagged_line[index])
        if byte == color_on and index + 1 < len(tagged_line):
            tag_type = ord(tagged_line[index + 1])
            index += 2
            if tag_type == color_addr:
                index = skip_address_payload(tagged_line, index, address_len)
            continue
        if byte == color_off and index + 1 < len(tagged_line):
            index += 2
            continue
        if byte == color_esc:
            index += 1
            if index < len(tagged_line):
                output.append(tagged_line[index])
                index += 1
            continue
        if byte == color_inv:
            index += 1
            continue
        output.append(tagged_line[index])
        index += 1
    return "".join(output)


def tagged_line_to_rich(runtime: IdaRuntime, tagged_line: str, style_map: dict[int, str]) -> Text:
    """Convert an IDA tagged line to rich Text.
    """
    color_on, color_off, color_esc, color_inv, color_addr, address_len = get_tag_constants(runtime)
    output = Text()
    style_stack: list[str] = []
    index = 0
    while index < len(tagged_line):
        byte = ord(tagged_line[index])
        if byte == color_on and index + 1 < len(tagged_line):
            tag_type = ord(tagged_line[index + 1])
            index += 2
            if tag_type == color_addr:
                index = skip_address_payload(tagged_line, index, address_len)
                continue
            style = style_map.get(tag_type, style_stack[-1] if style_stack else "")
            style_stack.append(style)
            continue
        if byte == color_off and index + 1 < len(tagged_line):
            index += 2
            if style_stack:
                style_stack.pop()
            continue
        if byte == color_esc:
            index += 1
            if index < len(tagged_line):
                output.append(tagged_line[index], style=style_stack[-1] if style_stack else "")
                index += 1
            continue
        if byte == color_inv:
            index += 1
            continue
        output.append(tagged_line[index], style=style_stack[-1] if style_stack else "")
        index += 1
    return output


def format_address(runtime: IdaRuntime, ea: int, mode: str) -> str:
    """Format address according to selected mode.
    """
    if mode == "va":
        return f"0x{ea:X}"
    image_base = int(runtime.ida_nalt.get_imagebase())
    if mode == "rva":
        return f"0x{ea - image_base:X}"
    offset = int(runtime.ida_loader.get_fileregion_offset(ea))
    if offset < 0 or offset == runtime.ida_idaapi.BADADDR:
        return "N/A"
    return f"0x{offset:X}"


def format_symbol_ref(runtime: IdaRuntime, name: str, ea: int, offsets_mode: str) -> str:
    """Format symbol reference as name@address.
    """
    return f"{name}@{format_address(runtime, ea, offsets_mode)}"


def format_at_address(runtime: IdaRuntime, ea: int, offsets_mode: str) -> str:
    """Format address for xref at-sites.
    """
    rendered = format_address(runtime, ea, offsets_mode)
    if rendered.startswith("0x"):
        return rendered[2:]
    return rendered


def get_function_stack_summary(runtime: IdaRuntime, func_ea: int) -> str | None:
    """Get stack frame summary for a function when available.
    """
    try:
        idc = importlib.import_module("idc")
    except Exception:
        return None

    get_frame_size = getattr(idc, "get_frame_size", None)
    if not callable(get_frame_size):
        return None
    with contextlib.suppress(Exception):
        frame_size = int(get_frame_size(func_ea))
        if frame_size >= 0:
            return f"frame=0x{frame_size:X}"
    return None


def output_rule(console: Console, use_rich: bool, title: str) -> None:
    """Output a titled separator.
    """
    if use_rich:
        console.rule(Text(title, style="yellow"), style="grey58")
        return
    width = 72
    prefix = f"--- {title} "
    fill = "-" * max(0, width - len(prefix))
    print(f"{prefix}{fill}")


def output_command_block(
    console: Console,
    use_rich: bool,
    commands: list[str],
    indent: int = 4,
) -> None:
    """Output command examples, syntax highlighted in rich mode.
    """
    if use_rich:
        block = "\n".join(f"$ {command}" for command in commands)
        syntax = Syntax(block, "bash", background_color="default")
        console.print(Padding(syntax, (0, 0, 0, indent)))
        return
    for command in commands:
        console.print(f"{' ' * indent}$ {command}")


def output_command_example(console: Console, use_rich: bool, command: str, indent: int = 4) -> None:
    """Output a single command example.
    """
    output_command_block(console, use_rich, [command], indent)


def strip_inline_code_markup(text: str) -> str:
    """Remove backtick wrappers from inline-code segments.
    """
    return INLINE_CODE_RE.sub(lambda match: match.group(1), text)


def render_inline_code_text(text: str) -> Text:
    """Render inline backtick segments with muted code styling.
    """
    rendered = Text()
    cursor = 0
    for match in INLINE_CODE_RE.finditer(text):
        if match.start() > cursor:
            rendered.append(text[cursor:match.start()], style="default")
        rendered.append(match.group(1), style="bright_black")
        cursor = match.end()
    if cursor < len(text):
        rendered.append(text[cursor:], style="default")
    return rendered


def output_tips_section(
    console: Console,
    use_rich: bool,
    tips: list[TipSuggestion],
    title_style: str | None = None,
    rule_style: str | None = None,
) -> None:
    """Render tips as description + muted command example lines.
    """
    if use_rich and title_style:
        console.rule(Text("Tips", style=title_style), style=rule_style or "grey58")
    else:
        output_rule(console, use_rich, "Tips")
    for tip in tips:
        if use_rich:
            line = Text("• ", style="grey58")
            line.append_text(render_inline_code_text(tip.description))
            console.print(line)
            if tip.command:
                console.print(Text(f"    $ {tip.command}", style="bright_black"))
        else:
            console.print(f"• {strip_inline_code_markup(tip.description)}")
            if tip.command:
                console.print(f"    $ {tip.command}")


def output_overview(
    runtime: IdaRuntime,
    file_path: Path,
    offsets_mode: str,
    use_rich: bool,
    console: Console,
) -> None:
    """Render file overview mode.
    """
    segments = get_segment_infos(runtime)
    entry_infos = get_export_infos(runtime)
    dll_exports = split_dll_exports(entry_infos)
    imports_grouped, total_imports = get_import_infos(runtime)
    total_functions, named_functions = get_function_counts(runtime)
    sample_function = get_sample_named_function(runtime)
    interesting_import = get_interesting_import(imports_grouped)

    image_base = int(runtime.ida_nalt.get_imagebase())
    entry_ea = int(runtime.ida_ida.inf_get_start_ea())
    entry_name = runtime.ida_name.get_name(entry_ea) or "(unnamed)"
    is_dll = is_dll_binary(runtime, file_path, dll_exports)

    procname = "unknown"
    inf_get_procname = getattr(runtime.ida_ida, "inf_get_procname", None)
    if callable(inf_get_procname):
        procname = str(inf_get_procname())

    if bool(runtime.ida_ida.inf_is_64bit()):
        bitness = "64-bit"
    elif bool(runtime.ida_ida.inf_is_32bit_exactly()):
        bitness = "32-bit"
    else:
        bitness = "16-bit"

    md5_hash, sha256_hash = compute_file_hashes(file_path)

    output_rule(console, use_rich, f"Overview: {file_path.name}")
    metadata_rows = [
        ("File", str(file_path)),
        ("Architecture", f"{procname} ({bitness})"),
        ("Image base", f"0x{image_base:X}"),
        ("Entry point", format_symbol_ref(runtime, entry_name, entry_ea, offsets_mode)),
        ("Functions", f"{total_functions} total, {named_functions} named"),
        ("MD5", md5_hash),
        ("SHA256", sha256_hash),
    ]
    if use_rich:
        metadata_table = Table(show_header=False, box=None, show_edge=False, pad_edge=False)
        metadata_table.add_column("Key", style="bright_black", no_wrap=True)
        metadata_table.add_column("Value")
        for key, value in metadata_rows:
            metadata_table.add_row(f"{key}:", value)
        console.print(metadata_table)
    else:
        for key, value in metadata_rows:
            console.print(f"{key}: {value}")

    output_rule(console, use_rich, "Segments")
    if use_rich:
        table = Table(show_header=True, header_style="bright_black", box=None, show_edge=False, pad_edge=False)
        table.add_column("Name")
        table.add_column("Start")
        table.add_column("End")
        table.add_column("Size")
        table.add_column("Perms")
        for segment in segments:
            table.add_row(
                segment.name,
                format_address(runtime, segment.start_ea, offsets_mode),
                format_address(runtime, segment.end_ea, offsets_mode),
                f"0x{segment.end_ea - segment.start_ea:X}",
                segment.permissions,
            )
        console.print(table)
    else:
        for segment in segments:
            console.print(
                f"{segment.name:16} {format_address(runtime, segment.start_ea, offsets_mode):>14} - "
                f"{format_address(runtime, segment.end_ea, offsets_mode):>14} "
                f"size=0x{segment.end_ea - segment.start_ea:X} perms={segment.permissions}"
            )

    visible_exports = dll_exports[:MAX_EXPORTS] if is_dll else []

    output_rule(console, use_rich, "Entry points")
    console.print(
        f"{format_address(runtime, entry_ea, offsets_mode)}  "
        f"{format_symbol_ref(runtime, entry_name, entry_ea, offsets_mode)} "
        "(OEP)"
    )
    for export in visible_exports:
        console.print(
            f"{format_address(runtime, export.ea, offsets_mode)}  "
            f"{format_symbol_ref(runtime, export.name, export.ea, offsets_mode)} "
            f"(export, ordinal {export.ordinal})"
        )
    skipped_entry_points = max(0, len(dll_exports) - len(visible_exports))
    if skipped_entry_points > 0:
        console.print(f"... {skipped_entry_points} entry points skipped")

    output_rule(console, use_rich, "Imports")
    visible_imports = sum(len(entries) for entries in imports_grouped.values())
    if not imports_grouped:
        console.print("(none)")
    else:
        for module, entries in sorted(imports_grouped.items(), key=lambda item: item[0].lower()):
            if use_rich:
                console.print(Text(f"[{module}]", style="yellow"))
            else:
                console.print(f"[{module}]")
            for entry in entries:
                console.print(format_symbol_ref(runtime, entry.name, entry.ea, offsets_mode))
    skipped_imports = max(0, total_imports - visible_imports)
    if skipped_imports > 0:
        console.print(f"... {skipped_imports} imports skipped")

    tips: list[TipSuggestion] = [
        TipSuggestion(
            "View the entry point.",
            f"idals {file_path} {format_address(runtime, entry_ea, 'va')}",
        ),
    ]
    if interesting_import is not None:
        tips.append(
            TipSuggestion(
                "This binary imports "
                f"`{format_symbol_ref(runtime, interesting_import.name, interesting_import.ea, offsets_mode)}` "
                "- view cross references to it.",
                f"python -m idals {file_path} {interesting_import.name} --after=1",
            )
        )
    if sample_function is not None:
        tips.append(
            TipSuggestion(
                "Explore a named function "
                f"`{format_symbol_ref(runtime, sample_function[1], sample_function[0], offsets_mode)}`.",
                f"idals {file_path} {sample_function[1]}",
            )
        )
    tips.append(
        TipSuggestion(
            f"Addresses shown as `{offsets_mode}`. Switch mode with `--offsets rva` or `--offsets file`.",
            f"idals {file_path} {format_address(runtime, entry_ea, 'va')} --offsets rva",
        )
    )

    output_tips_section(console, use_rich, tips)


def output_comment_line(console: Console, use_rich: bool, text: str, indent: int = 0) -> None:
    """Output a comment line with consistent styling.
    """
    prefix = " " * indent
    if use_rich:
        console.print(Text(prefix + text, style="bright_black"))
        return
    console.print(prefix + text)


def render_untagged_aux_body(body: str) -> Text:
    """Apply lightweight syntax styling to untagged listing lines.
    """
    if not body:
        return Text()
    if match := LABEL_PREFIX_RE.match(body):
        text = Text()
        text.append(match.group(1), style="bright_black")
        text.append(match.group(2))
        return text
    if ASSIGN_PREFIX_RE.match(body):
        return Text(body, style="bright_black")
    if match := NAME_PREFIX_RE.match(body):
        text = Text()
        text.append(match.group(1), style="yellow")
        text.append(match.group(2))
        return text
    return Text(body)


def render_listing_aux_line(runtime: IdaRuntime, raw_line: str, style_map: dict[int, str]) -> Text:
    """Render a non-main listing line with optional tag processing.
    """
    if line_has_tags(raw_line):
        return tagged_line_to_rich(runtime, raw_line, style_map)

    plain = strip_tagged_line(runtime, raw_line)
    if plain.lstrip().startswith(";"):
        if SIGNATURE_COMMENT_RE.match(plain.lstrip()):
            return Text(plain, style="yellow")
        return Text(plain, style="bright_black")

    body, separator, comment = plain.partition(";")
    text = render_untagged_aux_body(body)
    if separator:
        text.append(separator + comment, style="bright_black")
    return text


def output_xrefs_section(
    runtime: IdaRuntime,
    func_ctx: FunctionContext,
    offsets_mode: str,
    use_rich: bool,
    console: Console,
) -> None:
    """Render function xrefs as comment lines.
    """
    xrefs = func_ctx.xrefs_to
    if not xrefs:
        return

    visible = xrefs[:MAX_XREFS_INLINE]
    for xref in visible:
        if xref.from_func_name and xref.from_func_ea is not None:
            source = format_symbol_ref(runtime, xref.from_func_name, xref.from_func_ea, offsets_mode)
        else:
            source = get_xref_context(runtime, xref.from_addr, offsets_mode)
        output_comment_line(
            console,
            use_rich,
            f"; XREF: {format_address(runtime, xref.from_addr, offsets_mode)} (in {source})",
            indent=15,
        )

    if len(xrefs) > MAX_XREFS_INLINE:
        output_comment_line(
            console,
            use_rich,
            f"; XREF: ... showing first {MAX_XREFS_INLINE} of {len(xrefs)} callers",
            indent=15,
        )


def output_listing_lines(
    runtime: IdaRuntime,
    lines: list[ListingLine],
    target_head: int,
    offsets_mode: str,
    use_rich: bool,
    console: Console,
    style_map: dict[int, str],
) -> None:
    """Render listing lines.
    """
    for line in lines:
        for annotation in get_data_xref_annotations(runtime, line.ea, offsets_mode):
            output_comment_line(console, use_rich, annotation, indent=15)

        for anterior_line in line.anterior_lines:
            if use_rich:
                rendered_anterior = render_listing_aux_line(runtime, anterior_line, style_map)
                text = Text(" " * 15)
                text.append_text(rendered_anterior)
                console.print(text)
            else:
                console.print(f"{'':>14} {strip_tagged_line(runtime, anterior_line)}")

        prefix = format_address(runtime, line.ea, offsets_mode)
        if use_rich:
            text = Text(f"{prefix:>14} ", style="bright_black")
            text.append_text(tagged_line_to_rich(runtime, line.tagged_line, style_map))
            if line.ea == target_head:
                text.append("  ; <-- target", style="yellow")
            console.print(text)
        else:
            plain = strip_tagged_line(runtime, line.tagged_line)
            marker = "  ; <-- target" if line.ea == target_head else ""
            console.print(f"{prefix:>14} {plain}{marker}")

        for posterior_line in line.posterior_lines:
            if use_rich:
                rendered_posterior = render_listing_aux_line(runtime, posterior_line, style_map)
                text = Text(" " * 15)
                text.append_text(rendered_posterior)
                console.print(text)
            else:
                console.print(f"{'':>14} {strip_tagged_line(runtime, posterior_line)}")


def output_pseudocode(
    runtime: IdaRuntime,
    pseudocode_lines: list[str],
    use_rich: bool,
    console: Console,
    style_map: dict[int, str],
) -> None:
    """Render pseudocode lines.
    """
    if use_rich:
        console.print(Text("Pseudocode:", style="yellow"))
    else:
        console.print("Pseudocode:")
    for line in pseudocode_lines:
        if use_rich:
            console.print(tagged_line_to_rich(runtime, line, style_map))
        else:
            console.print(strip_tagged_line(runtime, line))


def output_address_view(
    runtime: IdaRuntime,
    file_path: Path,
    ea: int,
    before: int,
    after: int,
    offsets_mode: str,
    force_decompile: bool,
    suppress_decompile: bool,
    use_rich: bool,
    console: Console,
) -> None:
    """Render file+address mode.
    """
    style_map = build_tag_style_map(runtime)
    func_ctx = get_function_context(runtime, ea)
    heads = generate_listing_heads(runtime, ea, before, after, func_ctx)
    lines = generate_listing_lines(runtime, heads)

    target_head = ea
    get_head = getattr(runtime.ida_bytes, "get_item_head", None)
    if callable(get_head):
        target_head = int(get_head(ea))

    if func_ctx is not None:
        if not func_ctx.is_func_start and func_ctx.signature:
            signature_line = f"; {func_ctx.signature}"
            if use_rich:
                console.print(Text(" " * 15 + signature_line, style="yellow"))
            else:
                console.print(f"{'':>14} {signature_line}")
        if func_ctx.is_func_start:
            output_xrefs_section(runtime, func_ctx, offsets_mode, use_rich, console)

    if func_ctx is not None and heads:
        first_head = heads[0]
        if first_head > func_ctx.start_ea:
            omitted = count_heads_in_range(runtime, func_ctx.start_ea, first_head)
            if omitted > 0:
                output_comment_line(console, use_rich, f"; ...{omitted} instructions skipped...", indent=15)

    output_listing_lines(
        runtime,
        lines,
        target_head,
        offsets_mode,
        use_rich,
        console,
        style_map,
    )

    if func_ctx is not None and heads:
        last_rendered = heads[-1]
        last_func_line = get_last_function_line(runtime, func_ctx)
        if last_func_line is not None and last_rendered < last_func_line.ea:
            omitted_below = count_heads_in_range(runtime, last_rendered, last_func_line.ea)
            if omitted_below > 0:
                output_comment_line(console, use_rich, f"; ...{omitted_below} instructions skipped...", indent=15)
            output_listing_lines(
                runtime,
                [last_func_line],
                target_head,
                offsets_mode,
                use_rich,
                console,
                style_map,
            )

    if not suppress_decompile and func_ctx is not None and func_ctx.is_func_start:
        pseudocode_lines = get_pseudocode_lines(runtime, func_ctx.start_ea)
        if pseudocode_lines:
            if force_decompile or len(pseudocode_lines) <= MAX_PSEUDOCODE_LINES:
                output_pseudocode(runtime, pseudocode_lines, use_rich, console, style_map)
            else:
                console.print(
                    f"Pseudocode: {len(pseudocode_lines)} lines "
                    f"(use --decompile to force display)"
                )

    tips: list[TipSuggestion] = []
    if func_ctx is not None and not func_ctx.is_func_start:
        tips.append(
            TipSuggestion(
                "View the full function from the start, including its xrefs.",
                f"idals {file_path} 0x{func_ctx.start_ea:X} --after {func_ctx.instruction_count}",
            )
        )
    if func_ctx is not None and func_ctx.is_func_start and func_ctx.xrefs_to:
        tips.append(
            TipSuggestion(
                "View a caller of this function.",
                f"idals {file_path} 0x{func_ctx.xrefs_to[0].from_addr:X}",
            )
        )
    tips.append(
        TipSuggestion(
            "Show more context.",
            f"idals {file_path} 0x{ea:X} --after 64 --before 16",
        )
    )
    tips.append(
        TipSuggestion(
            f"Addresses shown as `{offsets_mode}`. Switch mode with `--offsets rva` or `--offsets file`.",
            f"idals {file_path} 0x{ea:X} --offsets rva",
        )
    )

    output_tips_section(console, use_rich, tips)


def run(argv: list[str]) -> int:
    """Run the CLI and return exit code.
    """
    if not argv:
        print_help_and_tutorial(use_rich=bool(sys.stdout.isatty()))
        return 0

    parser = build_argument_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 2
        return code

    if args.help:
        print_help_and_tutorial(use_rich=bool(sys.stdout.isatty()) and not bool(args.no_color))
        return 0

    if args.version:
        print(f"idals {__version__}")
        return 0

    if args.file is None:
        print_help_and_tutorial(use_rich=bool(sys.stdout.isatty()) and not bool(args.no_color))
        return 0

    if args.decompile and args.no_decompile:
        raise UsageError("--decompile and --no-decompile cannot be used together")
    if args.after < 0:
        raise UsageError("--after must be >= 0")
    if args.before < 0:
        raise UsageError("--before must be >= 0")

    file_path = Path(args.file)
    if not file_path.exists():
        raise AddressError(f"Error: File not found: {file_path}")

    stderr_console = Console(file=sys.stderr, markup=False, highlight=False)
    db_path = resolve_database(file_path, stderr_console)

    use_rich = bool(sys.stdout.isatty()) and not args.no_color
    console_width = None if use_rich else 10_000
    console = Console(
        file=sys.stdout,
        force_terminal=use_rich,
        no_color=not use_rich,
        markup=False,
        highlight=False,
        width=console_width,
    )

    with open_database_session(db_path, auto_analysis=False) as runtime:
        if args.address is None:
            output_overview(runtime, file_path, args.offsets, use_rich, console)
            return 0

        ea = resolve_address(runtime, args.address)
        output_address_view(
            runtime=runtime,
            file_path=file_path,
            ea=ea,
            before=args.before,
            after=args.after,
            offsets_mode=args.offsets,
            force_decompile=bool(args.decompile),
            suppress_decompile=bool(args.no_decompile),
            use_rich=use_rich,
            console=console,
        )
    return 0


def main() -> None:
    """CLI entry point.
    """
    try:
        code = run(sys.argv[1:])
    except UsageError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        code = 2
    except AddressError as exc:
        print(str(exc), file=sys.stderr)
        code = 1
    except AnalysisError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        code = 3
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        code = 3
    raise SystemExit(code)


if __name__ == "__main__":
    main()
