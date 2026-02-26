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
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

import idapro
import ida_auto
import ida_idaapi
import ida_loader
from ida_domain import Database
from ida_domain.comments import CommentKind, ExtraCommentKind
from ida_domain.database import IdaCommandOptions
from rich.console import Console
from rich.logging import RichHandler
from rich.padding import Padding
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

_IDAPRO_BOOTSTRAP = idapro

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
    disassembly: str
    anterior_lines: list[str]
    posterior_lines: list[str]


@dataclass
class TipSuggestion:
    description: str
    command: str | None = None


@dataclass(frozen=True)
class OffsetFormatter:
    mode: str
    image_base: int
    bad_address: int
    file_offset_resolver: Callable[[int], int]

    def format_address(self, ea: int) -> str:
        """Render an address in the configured mode.
        """
        if self.mode == "va":
            return f"0x{ea:X}"
        if self.mode == "rva":
            return f"0x{ea - self.image_base:X}"
        offset = int(self.file_offset_resolver(ea))
        if offset < 0 or offset == self.bad_address:
            return "N/A"
        return f"0x{offset:X}"


logger = logging.getLogger(__name__)


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
  --verbose              Enable debug logging to stderr
  --quiet                Show only errors on stderr
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
            ("--verbose", "Enable debug logging to stderr"),
            ("--quiet", "Show only errors on stderr"),
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
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("-v", "--version", action="store_true")
    return parser


def configure_logging(verbose: bool, quiet: bool, stderr_console: Console) -> None:
    """Configure stderr logging.
    """
    level = logging.WARNING
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.ERROR

    handler = RichHandler(
        console=stderr_console,
        rich_tracebacks=verbose,
        show_path=False,
        show_time=False,
        markup=False,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))

    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(level)
    logger.addHandler(handler)


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
        logger.debug("Using existing database: %s", file_path)
        return file_path

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    _, file_sha256 = compute_file_hashes(file_path)
    cache_path = CACHE_DIR / f"{file_sha256}.i64"
    if cache_path.exists():
        logger.debug("Cache hit for %s -> %s", file_path, cache_path)
        return cache_path

    logger.debug("Cache miss for %s; analyzing to %s", file_path, cache_path)
    stderr_console.print(f"Analyzing {file_path.name} (this may take a moment)...")
    ida_options = IdaCommandOptions(
        auto_analysis=True,
        new_database=True,
        output_database=str(cache_path),
        load_resources=True,
    )
    try:
        with Database.open(str(file_path), ida_options, save_on_close=True):
            ida_auto.auto_wait()
    except Exception as exc:
        raise AnalysisError(f"Analysis failed for {file_path}: {exc}") from exc

    if not cache_path.exists():
        raise AnalysisError(f"Analysis failed for {file_path}: did not create {cache_path}")
    logger.debug("Analysis completed: %s", cache_path)
    return cache_path


@contextlib.contextmanager
def open_database_session(db_path: Path, auto_analysis: bool = False) -> Iterator[Database]:
    """Open and close a database session.

    Raises:
        AnalysisError: If opening fails.

    """
    ida_options = IdaCommandOptions(auto_analysis=auto_analysis, new_database=False)
    logger.debug("Opening database session: %s (auto_analysis=%s)", db_path, auto_analysis)
    try:
        database = Database.open(str(db_path), ida_options, save_on_close=False)
    except Exception as exc:
        raise AnalysisError(f"Failed to open {db_path}: {exc}") from exc

    with database:
        if auto_analysis:
            ida_auto.auto_wait()
        yield database
    logger.debug("Closed database session: %s", db_path)


def get_permissions_string(db: Database, perm: int) -> str:
    """Format segment permissions as rwx triplet.
    """
    read_mask = 4
    write_mask = 2
    exec_mask = 1
    return f"{'r' if perm & read_mask else '-'}{'w' if perm & write_mask else '-'}{'x' if perm & exec_mask else '-'}"


def get_segment_infos(db: Database) -> list[SegmentInfo]:
    """Collect segment information.
    """
    segments: list[SegmentInfo] = []
    for index, segment in enumerate(db.segments.get_all()):
        name = db.segments.get_name(segment) or f"seg_{index}"
        segments.append(
            SegmentInfo(
                name=name,
                start_ea=int(segment.start_ea),
                end_ea=int(segment.end_ea),
                permissions=get_permissions_string(db, int(segment.perm)),
            )
        )
    return segments


def get_export_infos(db: Database) -> list[ExportInfo]:
    """Collect entry records from IDA's entry table.
    """
    exports: list[ExportInfo] = []
    badaddr = int(ida_idaapi.BADADDR)
    for entry in db.entries.get_all():
        ordinal = int(entry.ordinal)
        ea = int(entry.address)
        if ea == badaddr:
            continue
        name = str(entry.name or db.names.get_at(ea) or f"ord_{ordinal}")
        exports.append(ExportInfo(name=name, ea=ea, ordinal=ordinal))
    exports.sort(key=lambda item: (item.ea, item.ordinal, item.name.lower()))
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


def is_dll_binary(db: Database, file_path: Path, dll_exports: list[ExportInfo]) -> bool:
    """Determine whether the analyzed input is a DLL.
    """
    if file_path.suffix.lower() == ".dll":
        return True

    characteristics = parse_pe_characteristics(file_path)
    if characteristics is not None:
        return bool(characteristics & 0x2000)

    module_name = str(db.module or "")
    if module_name.lower().endswith(".dll"):
        return True

    return bool(dll_exports)


def get_import_infos(db: Database) -> tuple[dict[str, list[ImportInfo]], int]:
    """Collect imported symbols grouped by module.
    """
    imports: list[ImportInfo] = []
    for item in db.imports.get_all_imports():
        module = str(item.module_name or f"module_{item.module_index}")
        name = str(item.name or f"ord_{item.ordinal}")
        imports.append(ImportInfo(name=name, module=module, ea=int(item.address)))

    imports.sort(key=lambda entry: (entry.module.lower(), entry.name.lower(), entry.ea))
    total = len(imports)
    visible = imports[:MAX_IMPORTS]
    grouped: dict[str, list[ImportInfo]] = {}
    for item in visible:
        grouped.setdefault(item.module, []).append(item)
    return grouped, total


def get_function_counts(db: Database) -> tuple[int, int]:
    """Return (total functions, named functions).
    """
    total = 0
    named = 0
    for func in db.functions.get_all():
        total += 1
        func_name = db.functions.get_name(func) or ""
        if not func_name.startswith("sub_"):
            named += 1
    return total, named


def get_sample_named_function(db: Database) -> tuple[int, str] | None:
    """Pick one named function for tips.
    """
    for func in db.functions.get_all():
        name = db.functions.get_name(func) or ""
        if name and not name.startswith("sub_"):
            return int(func.start_ea), name
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


def is_mapped_address(db: Database, ea: int) -> bool:
    """Check whether address maps to a segment.
    """
    if ea == ida_idaapi.BADADDR:
        return False
    with contextlib.suppress(Exception):
        if db.segments.get_at(ea) is not None:
            return True
    return int(db.minimum_ea) <= ea < int(db.maximum_ea)


def get_name_entries(db: Database) -> list[tuple[int, str]]:
    """Collect names for fuzzy matching.
    """
    entries: list[tuple[int, str]] = []
    for ea, name in db.names.get_all():
        if name:
            entries.append((int(ea), str(name)))
    return entries


def resolve_name_ea(name_entries: list[tuple[int, str]], name: str) -> int | None:
    """Resolve symbol name to address from the name list.
    """
    exact_match: int | None = None
    folded_match: int | None = None
    folded_query = name.lower()
    for ea, candidate in name_entries:
        if candidate == name:
            exact_match = ea
            break
        if folded_match is None and candidate.lower() == folded_query:
            folded_match = ea
    return exact_match if exact_match is not None else folded_match


def build_unmapped_error(db: Database, ea: int) -> str:
    """Create mapped-range error message.
    """
    lines = [
        f"Error: Address 0x{ea:X} is not mapped in the binary.",
        "Valid address ranges:",
    ]
    for segment in get_segment_infos(db):
        lines.append(f"  {segment.name} 0x{segment.start_ea:X} - 0x{segment.end_ea:X}")
    lines.append("Tip: Use `idals <file>` (no address) to see the full memory layout.")
    return "\n".join(lines)


def build_symbol_not_found_error(name_entries: list[tuple[int, str]], symbol: str) -> str:
    """Create symbol-not-found message with suggestions.
    """
    names = [name for _, name in name_entries]
    close = difflib.get_close_matches(symbol, names, n=5, cutoff=0.6)
    lines = [f"Error: Symbol \"{symbol}\" not found."]
    if close:
        lines.append("Did you mean:")
        by_name = {name: ea for ea, name in name_entries}
        for candidate in close:
            lines.append(f"  {candidate}@0x{by_name[candidate]:X}")
    lines.append("Tip: Use `idals <file>` to inspect available imports/exports and names.")
    return "\n".join(lines)


def resolve_address(db: Database, address_str: str) -> int:
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
        if not is_mapped_address(db, ea):
            raise AddressError(build_unmapped_error(db, ea))
        return ea

    numeric_candidate: int | None = None
    if HEX_ADDRESS_RE.fullmatch(text):
        try:
            numeric_candidate = int(text, 16)
        except ValueError:
            numeric_candidate = None
        if numeric_candidate is not None and is_mapped_address(db, numeric_candidate):
            return numeric_candidate

    name_entries = get_name_entries(db)
    ea = resolve_name_ea(name_entries, text)
    if ea is not None and is_mapped_address(db, ea):
        return ea

    if numeric_candidate is not None:
        raise AddressError(build_unmapped_error(db, numeric_candidate))
    raise AddressError(build_symbol_not_found_error(name_entries, text))


def get_function_signature(db: Database, func_ea: int) -> str | None:
    """Get a function signature string when available.
    """
    func = db.functions.get_at(func_ea)
    if func is None:
        return None
    with contextlib.suppress(Exception):
        signature = db.functions.get_signature(func)
        if signature:
            return str(signature)
    return None


def count_heads_in_range(db: Database, start_ea: int, end_ea: int) -> int:
    """Count item heads in [start_ea, end_ea).
    """
    count = 0
    ea = start_ea
    while ea < end_ea:
        count += 1
        next_ea = db.bytes.get_next_head(ea)
        if next_ea is None:
            break
        next_int = int(next_ea)
        if next_int <= ea or next_int >= end_ea:
            break
        ea = next_int
    return count


def get_xrefs_to_function(db: Database, func_ea: int) -> list[XrefInfo]:
    """Collect xrefs to a function, capped.
    """
    xrefs: list[XrefInfo] = []
    for xref in db.xrefs.to_ea(func_ea):
        if len(xrefs) >= MAX_XREFS:
            break
        from_ea = int(xref.from_ea)
        caller_func = db.functions.get_at(from_ea)
        caller_name: str | None = None
        caller_ea: int | None = None
        if caller_func is not None:
            caller_ea = int(caller_func.start_ea)
            caller_name = db.functions.get_name(caller_func) or None
        xrefs.append(
            XrefInfo(
                from_addr=from_ea,
                from_func_name=caller_name,
                from_func_ea=caller_ea,
                xref_type=int(xref.type),
            )
        )
    return xrefs


def get_function_context(db: Database, ea: int) -> FunctionContext | None:
    """Find function context for address.
    """
    func = db.functions.get_at(ea)
    if func is None:
        return None

    start_ea = int(func.start_ea)
    end_ea = int(func.end_ea)
    name = db.functions.get_name(func) or f"sub_{start_ea:X}"
    signature = get_function_signature(db, start_ea)
    comment = db.functions.get_comment(func, False) or db.functions.get_comment(func, True)
    xrefs = get_xrefs_to_function(db, start_ea)
    instruction_count = count_heads_in_range(db, start_ea, end_ea)

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


def resolve_head_ea(db: Database, ea: int) -> int:
    """Resolve an address to its containing item head.
    """
    if db.bytes.is_head_at(ea):
        return ea
    previous_head = db.bytes.get_previous_head(ea)
    if previous_head is None:
        return ea
    return int(previous_head)


def generate_listing_heads(
    db: Database,
    target_ea: int,
    before: int,
    after: int,
    func_ctx: FunctionContext | None,
) -> list[int]:
    """Get list of heads around target, with function-boundary clamping.
    """
    head = resolve_head_ea(db, target_ea)

    min_ea = int(db.minimum_ea)
    max_ea = int(db.maximum_ea)
    lower_bound = func_ctx.start_ea if func_ctx else min_ea
    upper_bound = func_ctx.end_ea if func_ctx else max_ea

    before_heads: list[int] = []
    cursor = head
    for _ in range(before):
        previous = db.bytes.get_previous_head(cursor)
        if previous is None:
            break
        previous_ea = int(previous)
        if previous_ea < lower_bound:
            break
        before_heads.append(previous_ea)
        cursor = previous_ea
    before_heads.reverse()

    after_heads: list[int] = [head]
    cursor = head
    requested_after = max(after, 1)
    for _ in range(requested_after - 1):
        next_ea = db.bytes.get_next_head(cursor)
        if next_ea is None:
            break
        next_head = int(next_ea)
        if next_head >= upper_bound:
            break
        after_heads.append(next_head)
        cursor = next_head

    return before_heads + after_heads


def normalize_match_line(value: str) -> str:
    """Normalize listing lines for equality checks.
    """
    return " ".join(value.strip().split())


def normalize_comment_line(value: str) -> str:
    """Normalize a comment line for display.
    """
    comment = value.strip()
    if not comment:
        return ""
    if comment.startswith(";"):
        return comment
    return f"; {comment}"


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


def get_extra_comment_lines(db: Database, ea: int, kind: ExtraCommentKind) -> list[str]:
    """Get extra comments for a head.
    """
    output_lines: list[str] = []
    with contextlib.suppress(Exception):
        for raw_line in db.comments.get_all_extra_at(ea, kind):
            line = normalize_comment_line(str(raw_line))
            if line:
                output_lines.append(line)
    return output_lines


def get_item_comment_lines(db: Database, ea: int) -> list[str]:
    """Get regular and repeatable comments for an item.
    """
    lines: list[str] = []
    for kind in (CommentKind.REGULAR, CommentKind.REPEATABLE):
        info = db.comments.get_at(ea, kind)
        if info is None:
            continue
        line = normalize_comment_line(str(info.comment))
        if line:
            lines.append(line)
    return lines


def generate_listing_lines(db: Database, heads: list[int]) -> list[ListingLine]:
    """Generate disassembly lines for heads.
    """
    lines: list[ListingLine] = []
    for ea in heads:
        disassembly = str(db.bytes.get_disassembly_at(ea) or "").rstrip()
        if not disassembly:
            continue

        anterior_lines = get_extra_comment_lines(db, ea, ExtraCommentKind.ANTERIOR)
        posterior_lines = get_extra_comment_lines(db, ea, ExtraCommentKind.POSTERIOR)
        comment_lines = [] if ";" in disassembly else get_item_comment_lines(db, ea)
        posterior_lines = merge_unique_lines(posterior_lines, comment_lines)

        lines.append(
            ListingLine(
                ea=ea,
                disassembly=disassembly,
                anterior_lines=anterior_lines,
                posterior_lines=posterior_lines,
            )
        )
    return lines


def get_last_function_line(db: Database, func_ctx: FunctionContext) -> ListingLine | None:
    """Get the final instruction/data line in a function.
    """
    last_head = db.bytes.get_previous_head(func_ctx.end_ea)
    if last_head is None:
        return None
    last_head_ea = int(last_head)
    if last_head_ea < func_ctx.start_ea:
        return None
    lines = generate_listing_lines(db, [last_head_ea])
    return lines[0] if lines else None


def get_xref_context(db: Database, from_ea: int, formatter: OffsetFormatter) -> str:
    """Resolve the most useful xref context for a source address.
    """
    caller_func = db.functions.get_at(from_ea)
    if caller_func is not None:
        caller_ea = int(caller_func.start_ea)
        caller_name = db.functions.get_name(caller_func)
        if caller_name:
            return format_symbol_ref(caller_name, caller_ea, formatter)

    fallback_name = db.names.get_at(from_ea)
    if fallback_name:
        return format_symbol_ref(str(fallback_name), from_ea, formatter)

    return formatter.format_address(from_ea)


def get_data_xref_annotations(db: Database, ea: int, formatter: OffsetFormatter) -> list[str]:
    """Get data xrefs annotation lines for non-code items.
    """
    if db.bytes.is_code_at(ea):
        return []

    refs: list[str] = []
    seen_from: set[int] = set()
    for xref in db.xrefs.to_ea(ea):
        from_ea = int(xref.from_ea)
        if from_ea in seen_from:
            continue
        seen_from.add(from_ea)

        refs.append(
            f"; XREF: {formatter.format_address(from_ea)} "
            f"(in {get_xref_context(db, from_ea, formatter)})"
        )

    if not refs:
        return []
    if len(refs) > MAX_XREFS_INLINE:
        return [f"; XREF: {len(refs)} references"]
    return refs


def get_pseudocode_lines(db: Database, func_ea: int) -> list[str] | None:
    """Try to decompile a function.
    """
    func = db.functions.get_at(func_ea)
    if func is None or int(func.start_ea) != func_ea:
        return None

    try:
        pseudocode = db.functions.get_pseudocode(func, remove_tags=True)
    except Exception:
        return None

    lines = [str(line) for line in pseudocode]
    return lines if lines else None


def get_file_offset(ea: int) -> int:
    """Resolve file offset for an address.
    """
    return int(ida_loader.get_fileregion_offset(ea))


def build_offset_formatter(db: Database, mode: str) -> OffsetFormatter:
    """Build an address formatter for one output pass.
    """
    image_base = int(db.metadata.base_address or db.base_address or 0)
    return OffsetFormatter(
        mode=mode,
        image_base=image_base,
        bad_address=int(ida_idaapi.BADADDR),
        file_offset_resolver=get_file_offset,
    )


def format_symbol_ref(name: str, ea: int, formatter: OffsetFormatter) -> str:
    """Format symbol reference as name@address.
    """
    return f"{name}@{formatter.format_address(ea)}"


def format_at_address(ea: int, formatter: OffsetFormatter) -> str:
    """Format address for xref at-sites.
    """
    rendered = formatter.format_address(ea)
    if rendered.startswith("0x"):
        return rendered[2:]
    return rendered


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
    db: Database,
    file_path: Path,
    offsets_mode: str,
    use_rich: bool,
    console: Console,
) -> None:
    """Render file overview mode.
    """
    formatter = build_offset_formatter(db, offsets_mode)
    va_formatter = build_offset_formatter(db, "va")

    segments = get_segment_infos(db)
    entry_infos = get_export_infos(db)
    dll_exports = split_dll_exports(entry_infos)
    imports_grouped, total_imports = get_import_infos(db)
    total_functions, named_functions = get_function_counts(db)
    sample_function = get_sample_named_function(db)
    interesting_import = get_interesting_import(imports_grouped)

    image_base = int(db.metadata.base_address or db.base_address or 0)
    entry_ea = int(db.start_ip if db.start_ip is not None else db.minimum_ea)
    entry_name = str(db.names.get_at(entry_ea) or "(unnamed)")
    is_dll = is_dll_binary(db, file_path, dll_exports)

    architecture = str(db.metadata.architecture or db.architecture or "unknown")
    bitness_value = int(db.metadata.bitness or db.bitness or 0)
    bitness = f"{bitness_value}-bit" if bitness_value else "unknown"

    md5_hash, sha256_hash = compute_file_hashes(file_path)

    output_rule(console, use_rich, f"Overview: {file_path.name}")
    metadata_rows = [
        ("File", str(file_path)),
        ("Architecture", f"{architecture} ({bitness})"),
        ("Image base", f"0x{image_base:X}"),
        ("Entry point", format_symbol_ref(entry_name, entry_ea, formatter)),
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
                formatter.format_address(segment.start_ea),
                formatter.format_address(segment.end_ea),
                f"0x{segment.end_ea - segment.start_ea:X}",
                segment.permissions,
            )
        console.print(table)
    else:
        for segment in segments:
            console.print(
                f"{segment.name:16} {formatter.format_address(segment.start_ea):>14} - "
                f"{formatter.format_address(segment.end_ea):>14} "
                f"size=0x{segment.end_ea - segment.start_ea:X} perms={segment.permissions}"
            )

    visible_exports = dll_exports[:MAX_EXPORTS] if is_dll else []

    output_rule(console, use_rich, "Entry points")
    console.print(
        f"{formatter.format_address(entry_ea)}  "
        f"{format_symbol_ref(entry_name, entry_ea, formatter)} "
        "(OEP)"
    )
    for export in visible_exports:
        console.print(
            f"{formatter.format_address(export.ea)}  "
            f"{format_symbol_ref(export.name, export.ea, formatter)} "
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
                console.print(format_symbol_ref(entry.name, entry.ea, formatter))
    skipped_imports = max(0, total_imports - visible_imports)
    if skipped_imports > 0:
        console.print(f"... {skipped_imports} imports skipped")

    tips: list[TipSuggestion] = [
        TipSuggestion(
            "View the entry point.",
            f"idals {file_path} {va_formatter.format_address(entry_ea)}",
        ),
    ]
    if interesting_import is not None:
        tips.append(
            TipSuggestion(
                "This binary imports "
                f"`{format_symbol_ref(interesting_import.name, interesting_import.ea, formatter)}` "
                "- view cross references to it.",
                f"python -m idals {file_path} {interesting_import.name} --after=1",
            )
        )
    if sample_function is not None:
        tips.append(
            TipSuggestion(
                "Explore a named function "
                f"`{format_symbol_ref(sample_function[1], sample_function[0], formatter)}`.",
                f"idals {file_path} {sample_function[1]}",
            )
        )
    tips.append(
        TipSuggestion(
            f"Addresses shown as `{offsets_mode}`. Switch mode with `--offsets rva` or `--offsets file`.",
            f"idals {file_path} {va_formatter.format_address(entry_ea)} --offsets rva",
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


def render_listing_aux_line(raw_line: str) -> Text:
    """Render a non-main listing line.
    """
    plain = raw_line.rstrip()
    if plain.lstrip().startswith(";"):
        if SIGNATURE_COMMENT_RE.match(plain.lstrip()):
            return Text(plain, style="yellow")
        return Text(plain, style="bright_black")

    body, separator, comment = plain.partition(";")
    text = render_untagged_aux_body(body)
    if separator:
        text.append(separator + comment, style="bright_black")
    return text


def render_disassembly_line(raw_line: str) -> Text:
    """Render a main disassembly line.
    """
    body, separator, comment = raw_line.partition(";")
    text = Text(body.rstrip())
    if separator:
        text.append(separator + comment, style="bright_black")
    return text


def output_xrefs_section(
    db: Database,
    func_ctx: FunctionContext,
    formatter: OffsetFormatter,
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
            source = format_symbol_ref(xref.from_func_name, xref.from_func_ea, formatter)
        else:
            source = get_xref_context(db, xref.from_addr, formatter)
        output_comment_line(
            console,
            use_rich,
            f"; XREF: {formatter.format_address(xref.from_addr)} (in {source})",
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
    db: Database,
    lines: list[ListingLine],
    target_head: int,
    formatter: OffsetFormatter,
    use_rich: bool,
    console: Console,
) -> None:
    """Render listing lines.
    """
    for line in lines:
        for annotation in get_data_xref_annotations(db, line.ea, formatter):
            output_comment_line(console, use_rich, annotation, indent=15)

        for anterior_line in line.anterior_lines:
            if use_rich:
                rendered_anterior = render_listing_aux_line(anterior_line)
                text = Text(" " * 15)
                text.append_text(rendered_anterior)
                console.print(text)
            else:
                console.print(f"{'':>14} {anterior_line}")

        prefix = formatter.format_address(line.ea)
        if use_rich:
            text = Text(f"{prefix:>14} ", style="bright_black")
            text.append_text(render_disassembly_line(line.disassembly))
            if line.ea == target_head:
                text.append("  ; <-- target", style="yellow")
            console.print(text)
        else:
            marker = "  ; <-- target" if line.ea == target_head else ""
            console.print(f"{prefix:>14} {line.disassembly}{marker}")

        for posterior_line in line.posterior_lines:
            if use_rich:
                rendered_posterior = render_listing_aux_line(posterior_line)
                text = Text(" " * 15)
                text.append_text(rendered_posterior)
                console.print(text)
            else:
                console.print(f"{'':>14} {posterior_line}")


def output_pseudocode(
    pseudocode_lines: list[str],
    use_rich: bool,
    console: Console,
) -> None:
    """Render pseudocode lines.
    """
    if use_rich:
        console.print(Text("Pseudocode:", style="yellow"))
    else:
        console.print("Pseudocode:")
    for line in pseudocode_lines:
        if use_rich:
            console.print(render_disassembly_line(line))
        else:
            console.print(line)


def output_address_view(
    db: Database,
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
    formatter = build_offset_formatter(db, offsets_mode)
    func_ctx = get_function_context(db, ea)
    heads = generate_listing_heads(db, ea, before, after, func_ctx)
    lines = generate_listing_lines(db, heads)

    target_head = resolve_head_ea(db, ea)

    if func_ctx is not None:
        if not func_ctx.is_func_start and func_ctx.signature:
            signature_line = f"; {func_ctx.signature}"
            if use_rich:
                console.print(Text(" " * 15 + signature_line, style="yellow"))
            else:
                console.print(f"{'':>14} {signature_line}")
        if func_ctx.is_func_start:
            output_xrefs_section(db, func_ctx, formatter, use_rich, console)

    if func_ctx is not None and heads:
        first_head = heads[0]
        if first_head > func_ctx.start_ea:
            omitted = count_heads_in_range(db, func_ctx.start_ea, first_head)
            if omitted > 0:
                output_comment_line(console, use_rich, f"; ...{omitted} instructions skipped...", indent=15)

    output_listing_lines(
        db,
        lines,
        target_head,
        formatter,
        use_rich,
        console,
    )

    if func_ctx is not None and heads:
        last_rendered = heads[-1]
        last_func_line = get_last_function_line(db, func_ctx)
        if last_func_line is not None and last_rendered < last_func_line.ea:
            omitted_below = count_heads_in_range(db, last_rendered, last_func_line.ea)
            if omitted_below > 0:
                output_comment_line(console, use_rich, f"; ...{omitted_below} instructions skipped...", indent=15)
            output_listing_lines(
                db,
                [last_func_line],
                target_head,
                formatter,
                use_rich,
                console,
            )

    if not suppress_decompile and func_ctx is not None and func_ctx.is_func_start:
        pseudocode_lines = get_pseudocode_lines(db, func_ctx.start_ea)
        if pseudocode_lines:
            if force_decompile or len(pseudocode_lines) <= MAX_PSEUDOCODE_LINES:
                output_pseudocode(pseudocode_lines, use_rich, console)
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
    if args.verbose and args.quiet:
        raise UsageError("--verbose and --quiet cannot be used together")
    if args.after < 0:
        raise UsageError("--after must be >= 0")
    if args.before < 0:
        raise UsageError("--before must be >= 0")

    stderr_console = Console(file=sys.stderr, markup=False, highlight=False)
    configure_logging(verbose=bool(args.verbose), quiet=bool(args.quiet), stderr_console=stderr_console)

    file_path = Path(args.file)
    if not file_path.exists():
        raise AddressError(f"Error: File not found: {file_path}")

    logger.debug("Starting run for file: %s", file_path)
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

    with open_database_session(db_path, auto_analysis=False) as db:
        if args.address is None:
            logger.debug("Rendering overview")
            output_overview(db, file_path, args.offsets, use_rich, console)
            return 0

        ea = resolve_address(db, args.address)
        logger.debug("Rendering address view at 0x%X", ea)
        output_address_view(
            db=db,
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
