# idals — Design & Implementation Document

> **Version:** 0.1.0-draft
> **Status:** Ready for implementation
> **Companion document:** SPEC.md (behavioral specification)
> **Last updated:** 2026-02-22

## 1. Project Structure

`idals` is a **single Python file** using UV's inline script metadata for dependency declarations. The entire tool lives in one file: `idals.py`.

```
idals.py          # The entire tool — single file, standalone
```

### 1.1 UV Script Header

The file begins with PEP 723 inline script metadata:

```python
#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "idapro",
#     "ida-domain",
#     "rich",
# ]
# ///
```

This allows invocation via:

```bash
uv run idals.py malware.exe 0x140001000
```

Or, if installed/symlinked:

```bash
idals malware.exe 0x140001000
```


## 2. High-Level Architecture

The program follows a simple linear flow:

```
main()
  ├── parse_args()
  ├── if no args: print_help_and_tutorial()
  │
  ├── resolve_database(file_path)
  │   ├── if .i64/.idb → use directly
  │   └── if binary → hash → check cache → analyze if miss → return db path
  │
  ├── open_database(db_path)
  │
  ├── if no address: print_overview(db) → print_tips(db)
  │
  ├── if address:
  │   ├── resolve_address(db, address_str)
  │   ├── determine_context(db, ea) → function info, bounds, etc.
  │   ├── render_listing(db, ea, before, after, context)
  │   ├── maybe_render_pseudocode(db, ea, context)
  │   └── print_tips(db, ea, context)
  │
  └── close_database()
```


## 3. Module Dependencies & Imports

### 3.1 External Dependencies

| Package | Purpose | PyPI |
|---|---|---|
| `idapro` | IDA as a library — provides all `ida_*` modules | `pip install idapro` |
| `ida-domain` | Higher-level domain API for IDA | `pip install ida-domain` |
| `rich` | Terminal syntax highlighting and formatting | `pip install rich` |

### 3.2 IDA Python Modules Used

Prefer `ida-domain` where it provides the needed functionality. Fall back to these lower-level modules as needed:

| Module | Purpose |
|---|---|
| `idapro` | Library initialization, opening databases |
| `ida_auto` | Auto-analysis control (`auto_wait()`) |
| `ida_lines` | Line generation, tag removal, tag constants |
| `ida_funcs` | Function queries (`get_func`, `get_func_name`) |
| `ida_segment` | Segment enumeration |
| `ida_entry` | Entry points |
| `ida_name` | Name resolution (`get_name_ea`, `get_name`) |
| `ida_bytes` | Byte/head iteration (`next_head`, `prev_head`) |
| `ida_nalt` | File metadata, imports |
| `ida_xref` | Cross-reference queries |
| `ida_hexrays` | Decompiler access (optional/conditional) |
| `ida_ida` | Database info (`inf_get_min_ea`, `inf_get_max_ea`, `inf_get_start_ea`) |
| `ida_loader` | File offset conversion |
| `ida_idaapi` | `BADADDR` constant |
| `ida_typeinf` | Function type/signature info |
| `idautils` | Higher-level iteration helpers (`Functions()`, `Segments()`, `XrefsTo()`) |

### 3.3 Standard Library

| Module | Purpose |
|---|---|
| `argparse` | CLI argument parsing |
| `hashlib` | SHA-256 for cache keying |
| `pathlib` | Path manipulation |
| `sys` | stdout/stderr, exit codes, TTY detection |
| `os` | Environment, cache directory |
| `shutil` | File copy for caching |
| `textwrap` | Help text formatting |
| `difflib` | Fuzzy matching for "did you mean" suggestions |


## 4. Component Design

### 4.1 Argument Parsing

Use `argparse` with a custom help formatter. When no arguments are provided, bypass argparse entirely and call `print_help_and_tutorial()` — this avoids argparse's default error behavior for missing required args.

```python
def parse_args(argv: list[str]) -> argparse.Namespace:
    if not argv:
        print_help_and_tutorial()
        sys.exit(0)

    parser = argparse.ArgumentParser(
        prog="idals",
        add_help=False,  # We handle help ourselves
    )
    parser.add_argument("file", nargs="?")
    parser.add_argument("address", nargs="?")
    parser.add_argument("--after", "-A", type=int, default=16)
    parser.add_argument("--before", "-B", type=int, default=0)
    parser.add_argument("--offsets", choices=["va", "rva", "file"], default="va")
    parser.add_argument("--decompile", action="store_true")
    parser.add_argument("--no-decompile", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("-v", "--version", action="store_true")
    return parser.parse_args(argv)
```

### 4.2 Address Resolution

```python
def resolve_address(db, address_str: str) -> int:
    """Resolve a user-provided address string to an effective address (ea).

    Accepts:
      - Hex with prefix: "0x140001000"
      - Bare hex: "140001000" (if contains a-f or ambiguous, try hex first)
      - Symbol name: "main", "CreateFileW", "sub_140001000"

    Returns: ea (int)
    Raises: AddressError if unresolvable
    """
```

**Resolution order:**

1. If the string starts with `0x` or `0X`, parse as hex.
2. Try parsing as hex integer. If it succeeds and the resulting address is within the database's mapped range, use it.
3. Look up as a symbol name via `ida_name.get_name_ea(ida_idaapi.BADADDR, address_str)`.
4. If all fail, raise an error with fuzzy-match suggestions.

**Fuzzy matching for symbol suggestions:** Use `difflib.get_close_matches()` against a list of known names. To build the name list efficiently, iterate `idautils.Names()` — this yields `(ea, name)` pairs. Cache this list during the session. Limit suggestions to 5 matches.


### 4.3 Database Resolution & Caching

```python
def resolve_database(file_path: Path) -> Path:
    """Given an input file, return the path to a usable .i64 database.

    - If file_path is an .i64 or .idb, return it directly.
    - Otherwise, compute SHA-256, check cache, analyze if needed.

    Returns: Path to .i64 database
    """
```

**Cache directory:** `~/.cache/hex-rays/idals/`

Constructed via:
```python
cache_dir = Path.home() / ".cache" / "hex-rays" / "idals"
cache_dir.mkdir(parents=True, exist_ok=True)
```

**Cache key:** SHA-256 hex digest of the input file contents.

```python
def compute_file_hash(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
```

**Cache path:** `~/.cache/hex-rays/idals/<sha256>.i64`

**Analysis flow (cache miss):**

```python
import idapro

# Print progress to stderr (not stdout)
print(f"Analyzing {file_path.name} (this may take a moment)...", file=sys.stderr)

# Open and analyze (include -R so resources are loaded)
idapro.open_database(str(file_path), auto_analysis=True, args="-R")
ida_auto.auto_wait()

# Save to cache location
idapro.save_database(str(cache_path))
```

Note: The exact `idapro` / `ida-domain` API for opening and saving databases should be confirmed against the `ida-domain` `Database.open()` interface. The `ida-domain` `Database` context manager with `IdaCommandOptions(auto_analysis=True, new_database=True)` is preferred.


### 4.4 Database Access

Use `ida-domain`'s `Database.open()` context manager where possible:

```python
from ida_domain import Database
from ida_domain.database import IdaCommandOptions

options = IdaCommandOptions(auto_analysis=True, new_database=False)
with Database.open(str(db_path), options) as db:
    # All work happens within this context
    ...
```

For operations not yet exposed by `ida-domain`, import and use the lower-level `ida_*` modules directly within this context.


### 4.5 Overview Rendering

The overview mode gathers and renders:

**Metadata** — via `ida-domain`/IDA APIs plus local file hashing:
```python
metadata = db.metadata
min_ea = db.minimum_ea
max_ea = db.maximum_ea
md5, sha256 = compute_file_hashes(input_path)
```

Render metadata as aligned key/value rows using a borderless table in rich mode.

**Segments** — via `ida_segment`:
```python
for i in range(ida_segment.get_segm_qty()):
    seg = ida_segment.getnseg(i)
    name = ida_segment.get_segm_name(seg)
    start = seg.start_ea
    end = seg.end_ea
    perms = seg.perm  # bitmask: 1=exec, 2=write, 4=read
```

**Entry points** — via `ida_ida.inf_get_start_ea()` plus `ida_entry` enumeration.

Implementation detail:
- The first displayed row is always the original entry point (`inf_get_start_ea`) and is labeled `OEP`.
- For DLL inputs, additional rows are derived from `ida_entry` and treated as exports.
- Ordinals are displayed only for those DLL export rows, not for the original entry-point row.
- Entry-point/import section headers do not show `(visible/total)` counts; when output is truncated by caps, emit a trailing `... N <items> skipped` line.

```python
entry_ea = ida_ida.inf_get_start_ea()

for i in range(ida_entry.get_entry_qty()):
    ordinal = ida_entry.get_entry_ordinal(i)
    ea = ida_entry.get_entry(ordinal)
    name = ida_entry.get_entry_name(ordinal)
```

**Imports** — via `ida_nalt` import enumeration callback pattern:
```python
import ida_nalt

def imp_cb(ea, name, ordinal):
    # collect import info
    return True  # continue enumeration

for i in range(ida_nalt.get_import_module_qty()):
    module_name = ida_nalt.get_import_module_name(i)
    ida_nalt.enum_import_names(i, imp_cb)
```

**Function count** — via `idautils.Functions()`:
```python
functions = list(idautils.Functions())
total = len(functions)
named = sum(1 for ea in functions if not ida_funcs.get_func_name(ea).startswith("sub_"))
```


### 4.6 Listing Rendering (Lines API)

This is the core rendering engine. It uses IDA's lines API to produce output identical to what IDA shows in its listing view.

#### 4.6.1 Generating Lines for a Range

For each head (item) in the requested range, generate all associated output lines:

```python
import ida_lines
import ida_bytes

def generate_lines(start_ea: int, num_items_before: int, num_items_after: int,
                   func_start: int | None, func_end: int | None) -> list[tuple[int, str]]:
    """Generate tagged lines for a range of instructions/items.

    Returns list of (ea, tagged_line_text) tuples.
    Respects function boundaries if provided.
    """
    lines = []

    ea = start_ea
    before_items = []
    for _ in range(num_items_before):
        ea = ida_bytes.prev_head(ea, func_start or 0)
        if ea == ida_idaapi.BADADDR:
            break
        if func_start is not None and ea < func_start:
            break
        before_items.append(ea)
    before_items.reverse()

    after_items = [start_ea]
    ea = start_ea
    for _ in range(num_items_after - 1):
        ea = ida_bytes.next_head(ea, func_end or ida_idaapi.BADADDR)
        if ea == ida_idaapi.BADADDR:
            break
        if func_end is not None and ea >= func_end:
            break
        after_items.append(ea)

    all_items = before_items + after_items
    for item_ea in all_items:
        text = ida_lines.generate_disasm_line(item_ea, 0)
        if text:
            lines.append((item_ea, text))

    return lines
```

Important refinement: each instruction/item can emit multiple lines. The implementation should combine:

1. `ida_lines.generate_disassembly(ea, ...)` to collect the full line set for the head.
2. `ida_lines.get_extra_cmt(ea, ida_lines.E_PREV + i)` for anterior extra comments.
3. `ida_lines.generate_disasm_line(ea, 0)` for the main tagged disassembly line.
4. `ida_lines.get_extra_cmt(ea, ida_lines.E_NEXT + i)` for posterior extra comments.

Render in this order: anterior, main line, posterior.

#### 4.6.2 Tag Processing

IDA's generated lines contain embedded binary tags for syntax highlighting. The tag format:

- **Tag on:** `\x01` + type_byte (1 byte)
- **Tag off:** `\x02` + type_byte (1 byte)
- **Address tag:** `SCOLOR_ADDR` payload appears after tag-on and contains encoded EA text; skip the payload before continuing with visible operand text.

**For plain text mode:** Use `ida_lines.tag_remove(line)` which handles all tag stripping.

**For rich terminal mode:** Implement custom tag translation:

```python
import ida_lines
from rich.text import Text

# Mapping from IDA color tag types to rich styles
IDA_TAG_TO_STYLE: dict[int, str] = {
    ida_lines.COLOR_INSN:    "bold blue",        # instruction mnemonic
    ida_lines.COLOR_REG:     "cyan",             # register
    ida_lines.COLOR_NUMBER:  "bright_red",       # numeric constant
    ida_lines.COLOR_STRING:  "green",            # string literal
    ida_lines.COLOR_DNAME:   "yellow",           # data name
    ida_lines.COLOR_CNAME:   "yellow",           # code name
    ida_lines.COLOR_ASMDIR:  "magenta",          # assembler directive
    ida_lines.COLOR_AUTOCMT: "bright_black",     # automatic comment
    ida_lines.COLOR_REGCMT:  "bright_black",     # regular comment
    ida_lines.COLOR_RPTCMT:  "bright_black",     # repeatable comment
    ida_lines.COLOR_SEGNAME: "magenta",          # segment name
    ida_lines.COLOR_ADDR:    "bright_black",     # address in prefix
    ida_lines.COLOR_OPND1:   "white",            # first operand
    ida_lines.COLOR_OPND2:   "white",            # second operand
    # ... extend as needed
}

COLOR_ON  = 0x01  # Tag-on sentinel
COLOR_OFF = 0x02  # Tag-off sentinel
COLOR_ESC = 0x03  # Escape next char
COLOR_INV = 0x04  # Invisible text start
SCOLOR_ADDR = ida_lines.SCOLOR_ADDR  # Address tag type

def tagged_line_to_rich(tagged_line: str) -> Text:
    """Convert an IDA tagged line to a rich Text object with styling."""
    text = Text()
    i = 0
    style_stack = []

    while i < len(tagged_line):
        ch = ord(tagged_line[i])

        if ch == COLOR_ON:
            i += 1
            tag_type = ord(tagged_line[i])
            i += 1

            if tag_type == SCOLOR_ADDR:
                # Address tag: skip encoded EA payload based on IDA EA width.
                addr_len = 16 if ida_idaapi.BADADDR > 0xFFFFFFFF else 8
                i += addr_len
            else:
                style = IDA_TAG_TO_STYLE.get(tag_type, "")
                style_stack.append(style)
            continue

        elif ch == COLOR_OFF:
            i += 1
            tag_type = ord(tagged_line[i])
            i += 1
            if style_stack:
                style_stack.pop()
            continue

        elif ch == COLOR_ESC:
            i += 1
            if i < len(tagged_line):
                text.append(tagged_line[i], style=style_stack[-1] if style_stack else "")
                i += 1
            continue

        else:
            style = style_stack[-1] if style_stack else ""
            text.append(tagged_line[i], style=style)
            i += 1

    return text
```

**Note:** Resolve tag constants from `ida_lines` at runtime (`SCOLOR_ON`, `SCOLOR_OFF`, `SCOLOR_ADDR`, etc.) because values vary by API representation.


### 4.7 Function Context Detection

```python
def get_function_context(ea: int) -> FunctionContext | None:
    """Determine the function context for a given address.

    Returns None if the address is not within a function.
    """
    func = ida_funcs.get_func(ea)
    if func is None:
        return None

    return FunctionContext(
        start_ea=func.start_ea,
        end_ea=func.end_ea,
        name=ida_funcs.get_func_name(func.start_ea),
        is_func_start=(ea == func.start_ea),
        signature=get_function_signature(func.start_ea),
        comment=ida_funcs.get_func_cmt(func, repeatable=False)
                or ida_funcs.get_func_cmt(func, repeatable=True),
        xrefs_to=list(get_xrefs_to_function(func.start_ea)),
    )
```

**Xrefs to function:**

```python
def get_xrefs_to_function(func_ea: int) -> Iterator[XrefInfo]:
    """Yield cross-references to a function, capped at 100."""
    count = 0
    for xref in idautils.XrefsTo(func_ea, flags=0):
        if count >= 100:
            break
        caller_func = ida_funcs.get_func(xref.frm)
        yield XrefInfo(
            from_addr=xref.frm,
            from_func_name=ida_funcs.get_func_name(caller_func.start_ea) if caller_func else None,
            xref_type=xref.type,
        )
        count += 1
```


### 4.8 Pseudocode Rendering

```python
def render_pseudocode(func_ea: int) -> str | None:
    """Attempt to decompile the function and return pseudocode text.

    Returns None if:
      - Hex-Rays is not available
      - Decompilation fails
      - The address is not the start of a function
    """
    try:
        import ida_hexrays
        if not ida_hexrays.init_hexrays_plugin():
            return None
    except ImportError:
        return None

    func = ida_funcs.get_func(func_ea)
    if func is None or func.start_ea != func_ea:
        return None

    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if cfunc is None:
            return None
    except ida_hexrays.DecompilationFailure:
        return None

    # Get the pseudocode text (tagged)
    pseudocode = cfunc.get_pseudocode()
    lines = []
    for sl in pseudocode:
        lines.append(sl.line)  # Tagged line

    return lines  # Caller handles tag stripping/rich rendering
```

The pseudocode lines use the same IDA tag format as disassembly lines, so the same `tag_remove()` / `tagged_line_to_rich()` pipeline handles them.


### 4.9 Address Formatting

```python
def format_address(ea: int, mode: str, image_base: int) -> str:
    """Format an address according to the selected addressing mode.

    Args:
        ea: effective (virtual) address
        mode: "va", "rva", or "file"
        image_base: the binary's image base address

    Returns: formatted address string
    """
    if mode == "va":
        return f"0x{ea:X}"
    elif mode == "rva":
        return f"0x{ea - image_base:X}"
    elif mode == "file":
        # Convert VA to file offset
        offset = ida_loader.get_fileregion_offset(ea)
        if offset == -1:
            return "N/A"
        return f"0x{offset:X}"
```

**Image base** can be retrieved via `ida_nalt.get_imagebase()`.


### 4.10 Tips Generation

Tips are context-sensitive suggestions printed at the bottom of every output (except the no-args help mode, which has its own comprehensive examples). Runtime output includes tip descriptions and optional command examples; in rich mode command lines are muted.

```python
@dataclass
class TipSuggestion:
    description: str
    command: str | None = None


def generate_tips(
    db_context,
    address: int | None,
    func_context: FunctionContext | None,
) -> list[TipSuggestion]:
    """Generate contextual tips based on what was just displayed."""
    tips: list[TipSuggestion] = []

    if address is None:
        entry = ida_ida.inf_get_start_ea()
        tips.append(
            TipSuggestion(
                "View the entry point.",
                f"idals {db_context.file_name} 0x{entry:X}",
            )
        )

        if db_context.interesting_imports:
            imp = db_context.interesting_imports[0]
            tips.append(
                TipSuggestion(
                    f"This binary imports {imp.name}@0x{imp.ea:X} - view cross references to it.",
                    f"python -m idals {db_context.file_name} {imp.name} --after=1",
                )
            )

        if db_context.sample_named_function:
            fn = db_context.sample_named_function
            tips.append(
                TipSuggestion(
                    "Explore a named function.",
                    f"idals {db_context.file_name} {fn.name}",
                )
            )

    else:
        if func_context and not func_context.is_func_start:
            tips.append(
                TipSuggestion(
                    "View the full function from the start.",
                    f"idals {db_context.file_name} 0x{func_context.start_ea:X} "
                    f"--after {func_context.instruction_count}",
                )
            )

        if func_context and func_context.xrefs_to:
            first_caller = func_context.xrefs_to[0]
            tips.append(
                TipSuggestion(
                    "View a caller of this function.",
                    f"idals {db_context.file_name} 0x{first_caller.from_addr:X}",
                )
            )

        tips.append(
            TipSuggestion(
                "Show more context.",
                f"idals {db_context.file_name} 0x{address:X} --after 64 --before 16",
            )
        )
        tips.append(
            TipSuggestion(
                "View as file offsets (for patching).",
                f"idals {db_context.file_name} 0x{address:X} --offsets file",
            )
        )

    return tips
```

**Interesting imports heuristic:** Prioritize well-known security-relevant imports like `VirtualAlloc`, `CreateProcess`, `WriteProcessMemory`, `LoadLibrary`, `RegOpenKey`, `InternetOpenUrl`, `NtCreateThread`, etc. Maintain a small hardcoded list of "notable" API names and surface whichever ones appear in the binary.


### 4.11 Output Rendering Pipeline

The final rendering pipeline ties everything together:

```python
from rich.console import Console
from rich.text import Text


def output_tips(console: Console, tips: list[TipSuggestion], use_rich: bool) -> None:
    if use_rich:
        console.rule(Text("Tips", style="yellow"), style="grey58")
        for tip in tips:
            bullet = Text("• ", style="grey58")
            bullet.append_text(render_inline_code_text(tip.description))
            console.print(bullet)
            if tip.command:
                console.print(Text(f"    $ {tip.command}", style="bright_black"))
    else:
        print("\n--- Tips " + "-" * 63)
        for tip in tips:
            print(f"• {strip_inline_code_markup(tip.description)}")
            if tip.command:
                print(f"    $ {tip.command}")
```

**TTY detection:**
```python
use_rich = sys.stdout.isatty() and not args.no_color
```


## 5. Data Types

Keep these minimal — use `dataclasses` or `NamedTuple` for internal structure:

```python
from dataclasses import dataclass, field

@dataclass
class FunctionContext:
    start_ea: int
    end_ea: int
    name: str
    is_func_start: bool
    signature: str | None
    comment: str | None
    xrefs_to: list["XrefInfo"]

    @property
    def instruction_count(self) -> int:
        """Approximate instruction count for the function."""
        count = 0
        ea = self.start_ea
        while ea < self.end_ea and ea != ida_idaapi.BADADDR:
            count += 1
            ea = ida_bytes.next_head(ea, self.end_ea)
        return count

@dataclass
class XrefInfo:
    from_addr: int
    from_func_name: str | None
    xref_type: int

@dataclass
class SegmentInfo:
    name: str
    start_ea: int
    end_ea: int
    permissions: str  # e.g., "r-x", "rw-"

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
```


## 6. Main Entry Point

```python
def main():
    args = parse_args(sys.argv[1:])

    if args.help or args.file is None:
        print_help_and_tutorial()
        sys.exit(0)

    if args.version:
        print(f"idals {__version__}")
        sys.exit(0)

    file_path = Path(args.file)
    if not file_path.exists():
        print(f"Error: File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    # Resolve to a database
    try:
        db_path = resolve_database(file_path)
    except AnalysisError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(3)

    # Open database and do work
    try:
        options = IdaCommandOptions(auto_analysis=False, new_database=False)
        with Database.open(str(db_path), options) as db:
            use_rich = sys.stdout.isatty() and not args.no_color

            if args.address is None:
                # Overview mode
                content = build_overview(db, file_path)
            else:
                # Address mode
                ea = resolve_address(db, args.address)
                func_ctx = get_function_context(ea)
                content = build_listing(
                    db, ea, func_ctx,
                    before=args.before,
                    after=args.after,
                    offsets_mode=args.offsets,
                    show_decompile=args.decompile,
                    hide_decompile=args.no_decompile,
                    file_path=file_path,
                )

            render_output(content, use_rich)

    except AddressError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
```


## 7. Help Text Content

The no-args help output is a critical part of the UX. It should be a self-contained tutorial.

In rich mode:
- section titles are yellow
- option names in the OPTIONS section are blue
- decorative rules and bullet markers are muted/grey
- EXAMPLES are rendered as a syntax-highlighted command block (instead of coloring full rows)

In plain mode, render equivalent uncolored text.

Here is the structure (the implementer should flesh out the full text):

```
idals — IDA Pro-powered binary inspection from the command line

USAGE
  idals <file>                                  Show binary overview (sections, entry points, imports)
  idals <file> <address>                        Show disassembly at address (--after defaults to 16)
  idals <file> <symbol>                         Show disassembly at named symbol
  idals <file> <address> --after N              Show N instructions/items after address
  idals <file> <address> --before N             Show N instructions/items before address
  idals <file> <address> --after N --before M   Show context around address

ADDRESS FORMATS
  0x140001000                       Hex with prefix
  140001000                         Bare hex (if contains a-f digits)
  main                              Symbol name
  CreateFileW                       Import name
  sub_140001000                     Auto-generated function name

OPTIONS
  --after N, -A          Instructions/items after target (default: 16)
  --before N, -B         Instructions/items before target (default: 0)
  --offsets va|rva|file  Address display mode (default: va)
  --decompile            Force showing pseudocode
  --no-decompile         Suppress pseudocode
  --no-color             Plain text output (no syntax highlighting)

EXAMPLES
  # Quick triage: what's in this binary?
  $ idals suspicious.exe

  # Look at the entry point from the overview output
  $ idals suspicious.exe 0x140001000

  # A debugger told me execution stopped here — what's the code?
  $ idals suspicious.exe 0x14000A230

  # Look at a function by name
  $ idals suspicious.exe main

  # See an entire small function with lots of context
  $ idals suspicious.exe sub_140001000 --after 128

  # Check what's around a crash address (before and after)
  $ idals suspicious.exe 0x14000BEEF --after 8 --before 8

  # Get file offsets for patching
  $ idals suspicious.exe 0x140001000 --offsets file

COMMON MISTAKES
  # Wrong: passing a decimal number (interpreted as hex if valid hex)
  $ idals file.exe 1234
  # If you mean decimal, prefix with 0d or convert to hex first

  # Wrong: address not in any segment
  $ idals file.exe 0xDEAD
  # idals will show valid ranges — pick an address from those

TIPS
  • First time? Start by inspecting the binary overview.
    $ idals <file>
  • Cross-references are shown inline — follow addresses to explore.
  • Search for call instructions in a larger context window.
    $ idals file.exe main --after 128 | grep -i "call"
  • Browse long output with paging while preserving color.
    $ idals file.exe main --after 128 | less -R
  • Cache: analyzed databases are cached at ~/.cache/hex-rays/idals/
    Delete this directory to force re-analysis.
```


## 8. Testing Strategy

While not part of the initial single-file deliverable, the implementer should consider:

- **Manual smoke tests:** Run against a known PE (e.g., `notepad.exe`), a known ELF, and a known `.i64` database.
- **Verify caching:** Run twice on the same binary, confirm second run is fast.
- **Verify TTY detection:** Run piped (`| cat`) vs. interactive.
- **Verify function boundaries:** Request 16 instructions/items at a function that's only 5 instructions long — confirm it stops at the end.
- **Verify symbol resolution:** Test with known export names, known function names, and typos.
- **Verify all addressing modes:** Compare VA, RVA, and file offset output for the same address.


## 9. Known Risks & Open Questions

| Risk | Mitigation |
|---|---|
| `ida-domain` API may not expose all needed functionality (e.g., lines API) | Fall back to `ida_*` modules directly; `ida-domain` is complementary |
| Tag parsing byte values may vary across IDA versions | Verify constants from `ida_lines` module at runtime, not hardcoded |
| Address tag payload width can differ between IDA runtime builds and input binary bitness | Derive width from IDA EA size (`ida_idaapi.BADADDR`), and skip address payload defensively |
| `idalib` analysis on large binaries may be slow | The caching strategy mitigates this for repeat invocations; print progress to stderr |
| Hex-Rays decompiler may not be available | Detect at runtime via `ida_hexrays.init_hexrays_plugin()`, gracefully degrade |
| Large binaries may have thousands of imports/entry records | Cap listings with a note about total count |
| `ida-domain` `Database.open()` vs `idapro.open_database()` lifecycle management | Follow `ida-domain` examples; test both paths |


## 10. Future Extensions (Out of Scope for v0.1)

Documented here for context, not for implementation:

- **Dedicated cross-reference mode** (`idals file.exe --xrefs 0x140001000`) — show all xrefs to/from an address in a structured format.
- **String search** (`idals file.exe --strings`) — list identified strings with addresses.
- **Function listing** (`idals file.exe --functions`) — list all functions with sizes and call counts.
- **Diffing** (`idals file1.exe 0x1000 | diff - <(idals file2.exe 0x1000)`) — already works via standard Unix tools.
- **Struct/type rendering** — show resolved structure layouts for data items.
- **MCP server mode** — expose `idals` capabilities as MCP tools for tighter agent integration.

