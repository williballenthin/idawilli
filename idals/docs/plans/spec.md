# idals — Behavioral Specification

> **Version:** 0.1.0.dev0
> **Status:** Ready for implementation
> **Last updated:** 2026-02-23

## 1. Overview

`idals` is a command-line tool that wraps IDA Pro's analysis engine (via `idalib`) to provide instant, richly-annotated disassembly and decompilation output to standard output. It is designed to be used by both LLM-powered agents (software engineering agents, reverse engineering agents, malware analysts) and human reverse engineers.

The name follows the Unix convention of `ls` — it *lists* the contents of a binary at a given address, the same way `ls` lists the contents of a directory.

### 1.1 Motivations

**For agents:** LLM-powered agents performing tasks like malware triage, vulnerability research, and binary analysis currently either build ad-hoc disassembly using basic libraries (capstone, pefile) — which lacks cross-references, type information, and semantic analysis — or invoke full IDA Python scripts, which require complex setup and code execution environments. `idals` provides a single command that delivers IDA's full analysis power with zero ceremony.

**For humans:** When an agent produces analysis referencing specific addresses and functions, a human analyst can reproduce exactly the same view by running the same `idals` command. The tool is also independently useful for quick triage from the terminal — examining crash dump addresses, debugger output, or specific functions without launching the full IDA GUI.

**Design philosophy:** The tool should be radically easy to use. A person or agent encountering it for the first time should be able to invoke it with no arguments, read the output, and immediately be productive. It should be self-documenting, provide few-shot examples in its help output, and suggest next steps after every invocation.


## 2. Invocation Modes

### 2.1 No Arguments — Help & Tutorial

```
$ idals
```

When invoked with no arguments, `idals` prints comprehensive, self-contained documentation including:

- **Tool description** — what it does, who it's for, what it wraps.
- **Usage synopsis** — the different invocation patterns.
- **Modes of operation** — overview of each mode with brief descriptions.
- **Few-shot examples** — concrete, copy-pasteable examples showing both good and bad usage patterns. These should demonstrate:
  - Opening a binary and viewing the overview.
  - Viewing disassembly at a hex address.
  - Viewing a function by name.
  - Adjusting the context window with `--after` and `--before`.
  - Switching addressing modes.
  - Common mistakes and how to fix them.
- **Tips & tricks** — practical advice for effective use, such as:
  - How to chain `idals` with `grep` to search for patterns.
  - How to use symbol names instead of addresses.
  - How to find the right address from a crash dump or debugger.
  - Workflow patterns for agents: start with overview, identify interesting functions, drill into each.
  - How addressing modes relate to different tasks (VA for runtime, RVA for position-independent analysis, file offset for patching).

The help output should be written with the assumption that the reader has never seen the tool before and may be an LLM agent that was simply told "use idals to look at binaries." It should be thorough enough that a single read gives the reader everything they need.


### 2.2 File Only — Binary Overview

```
$ idals <file>
```

When invoked with only a file path and no address, `idals` provides a high-level overview of the binary, including:

#### Required Information

- **File metadata:** filename, architecture/bitness, image base address, function counts, plus input-file MD5 and SHA256.
- **Entry points:** list where the first item is always the binary's original entry point, labeled as `OEP` (address and name, if named).
- **Segments/sections:** a table showing each segment's name, virtual address range, size, and permissions (rwx). This communicates the valid address space.
- **DLL exports (DLLs only):** after the original entry point, include exported functions/symbols with addresses. Ordinals are shown only for these export entries. Exports are capped at a reasonable limit (for example 50) with a note about truncation.
- **Imports:** list of imported functions grouped by module/library (capped similarly).
- **Functions:** total count of identified functions. Optionally, a summary of named vs. unnamed functions.

Decision note: the overview uses the heading `Entry points` instead of `Exports` because this section represents invocation starts, not only symbol exports. The original entry point is always listed first as `OEP` to support first-step exploration for both executables and DLLs. DLL export rows follow, and only those rows include ordinals. Section headers do not include `(visible/total)` counters; if capped output omits rows, emit a trailing `... N <items> skipped` line.

#### Tips Section

At the bottom, under a heading like `Tips`, the output should include concrete, binary-specific suggestions. Each tip should be rendered as:

- a bullet description line
- an indented command example line (when applicable)

In rich output, command example lines should be visually muted (dim/gray style). Verbatim inline fragments in tip descriptions (addresses, symbols, flags) should be rendered with a muted code-like style.

Examples:

- "View the entry point." + `idals <file> 0x<entrypoint>`
- "View a specific import." + `idals <file> CreateProcessW`
- "List disassembly around an address from your debugger." + `idals <file> 0x<addr> --after 32`
- "This binary imports VirtualAlloc@0x... - view cross references to it." + `python -m idals <file> VirtualAlloc --after=1`
- "Switch to file offsets for patching." + `idals <file> 0x<addr> --offsets file`

Tips should be tailored to the specific binary where possible (referencing actual addresses, actual import names, actual function names).


### 2.3 File + Address — Disassembly View

```
$ idals <file> <address>
```

This is the primary mode. Given a file and an address, `idals` renders the IDA listing output (via the lines API) for that location.

#### Address Input Formats

The `<address>` argument accepts:

- **Hex with prefix:** `0x140001000`, `0X140001000`
- **Bare hex:** `140001000` (interpreted as hex if it contains a-f characters or is longer than typical decimal values; see implementation notes)
- **Symbol name:** `main`, `CreateFileW`, `sub_140001000`, `.text` — resolved via IDA's name resolution. If the name is ambiguous, prefer functions over data. If not found, print an error with suggestions (e.g., "did you mean...?" with close matches).

#### Default Context

By default, the tool shows **16 instructions/items** forward from the given address and **0 instructions/items** backward. Each instruction/item may produce multiple output lines (due to comments, labels, cross-reference annotations, etc.). For each head, render lines in this order: anterior lines, main disassembly line, posterior lines. Use the IDA lines APIs to enumerate these lines.

#### Context Flags

- **`--after N`** (alias: `-A`): show N instructions/items after the target address (default: 16).
- **`--before N`** (alias: `-B`): show N instructions/items before the target address (default: 0).

Short aliases follow the `grep -A` / `grep -B` convention.

#### Function Boundary Clamping

The rendered output **never crosses function boundaries:**

- If rendering forward and the end of the containing function is reached before N instructions/items, stop at the function's last instruction.
- If rendering backward and the start of the containing function is reached before N instructions/items, stop at the function's first instruction.
- This prevents confusing output where unrelated code from adjacent functions appears in the listing.

#### Function Context

When the target address falls within a recognized function:

1. **Function xrefs at function start only:** when the target is the function start, render cross-references as `; XREF: 0xINSN_ADDRESS (in caller_name@0xCALLER_START)`. If there are more than 10, show the first 10 and then a truncation note.
2. **Signature context for mid-function targets:** when the target is inside a function (not at start), render a signature comment line `; <signature>` before the listing when available.
3. **Disassembly:** render listing lines for the requested range.
4. **Skipped-range marker:** if the output starts or ends inside a larger function body, render an indented comment line using the exact phrase `; N instructions skipped`, then show the final function instruction when truncating the tail.
5. **Pseudocode** (if applicable — see §2.4).

If the address is not within a function (e.g., data, unanalyzed bytes), render only the listing.


### 2.4 Pseudocode (Decompilation)

When all of the following conditions are met, `idals` also emits the Hex-Rays pseudocode for the function:

1. The Hex-Rays decompiler is available (i.e., `ida_hexrays` can be imported and a decompiler for the current architecture is licensed).
2. The target address is the start of a function (or resolves to one via symbol name).
3. The decompiled output is **64 lines or fewer**.

The pseudocode is rendered **after** the disassembly, under a clear separator/heading like:

```
─── Pseudocode ───────────────────────────────────────────
```

If the decompiled output exceeds 64 lines, it is **not shown**, and a note is printed instead:

```
Pseudocode: 142 lines (use --decompile to force display)
```

A `--decompile` flag can be provided to force pseudocode output regardless of length. A `--no-decompile` flag suppresses pseudocode entirely.

The pseudocode should use the same tag-stripping or rich-markup rendering as the disassembly (see §3).


## 3. Output Rendering

### 3.1 Plain Text Mode (Non-Interactive)

When stdout is not a TTY (i.e., output is piped to another program, captured by an agent, or redirected to a file), all output is **plain text**:

- IDA's binary tag markers (COLOR_ON = `\x01`, COLOR_OFF = `\x02`, plus the type byte) are stripped using `ida_lines.tag_remove()` or equivalent logic.
- The embedded address tag (`SCOLOR_ADDR`) is handled specially: skip the encoded address payload (derived from IDA EA width; typically 16 hex chars in IDA64) and retain only the visible operand text.
- No ANSI escape codes or rich markup in the output.

### 3.2 Rich Terminal Mode (Interactive)

When stdout is a TTY (human at a terminal), the output is syntax-highlighted using the `rich` library:

- IDA's binary tags are translated to `rich` markup. Each tag type maps to a color/style. The exact color scheme is implementation-defined and can be tuned, but a reasonable starting point:
  - **Instructions/mnemonics** (`COLOR_INSN`): bold blue
  - **Registers**: cyan
  - **Numeric constants** (`COLOR_NUMBER`): light red / salmon
  - **Strings** (`COLOR_STRING`): green
  - **Names/labels** (`COLOR_DNAME`, `COLOR_CNAME`, etc.): yellow
  - **Comments** (`COLOR_AUTOCMT`, `COLOR_REGCMT`): gray / dim
  - **Addresses** in the prefix: dim white
  - **Segment names**: magenta
- The address tag requires special handling: after the tag-on sentinel and address tag type byte, skip the encoded address payload based on IDA EA width (commonly 16 hex chars), then continue parsing the visible text that follows.
- The `rich` Console should be used for output, allowing automatic terminal width detection and proper handling of wide content.

### 3.3 Structural Elements

Regardless of rendering mode, the output uses these structural conventions:

- Address view has no dedicated function heading line.
- Omitted content markers are indented comment lines using the exact phrase `; N instructions skipped`.
- Tips are rendered as bullet descriptions with optional indented command lines; in rich mode those command lines are muted.
- In rich mode, section rules use a muted/gray line with a yellow section title.
- Overview metadata is rendered as aligned key/value rows (no box borders), and segment tables omit decorative borders.
- Overview entry-point/import rows are left-aligned.


## 4. Addressing Modes

All addresses in `idals` output are displayed in one of three modes, controlled by a `--offsets` flag:

| Flag Value | Description | Use Case |
|---|---|---|
| `va` (default) | Virtual address / effective address as mapped in memory | Runtime analysis, debugger correlation |
| `rva` | Relative virtual address (offset from image base) | Position-independent analysis, ASLR-aware work |
| `file` | File offset (byte position in the original file) | Patching, hex editing, binary diffing |

```
$ idals malware.exe 0x140001000 --offsets rva
$ idals malware.exe 0x140001000 --offsets file
```

The addressing mode affects:
- The address prefix on each disassembly line.
- The addresses shown in cross-reference listings.

The output should always include a tips entry indicating the active addressing mode and how to switch modes with `--offsets rva` and `--offsets file`.


## 5. Inline Cross-Reference Annotations

`idals` enriches the listing output with cross-reference information, injected as comments:

### 5.1 Instruction Cross-References

When an instruction references another location (a call target, a data reference, a jump target to a named location), and IDA has cross-reference information for it, `idals` may inject an inline comment showing:

- The target's **name** (if known) and **address**.
- For indirect references through pointers, the resolved target if available.

This is primarily useful for references that aren't already visible in IDA's default rendering. If IDA already shows the name in the operand (e.g., `call CreateFileW`), no additional annotation is needed.

### 5.2 Data Cross-References

When viewing data items that have cross-references to them (i.e., code or data that references this location), and there are **10 or fewer** such references, they are listed as comments near the data item:

```
.data:0x140010000  g_config        dd 0            ; XREF: 0x140001020 (in sub_140001000@0x140001000)
                                                    ; XREF: 0x140002044 (in sub_140002000@0x140002000)
```

If there are more than 10 references, just show the count:
```
.data:0x140010000  g_config        dd 0            ; XREF: 47 references
```

### 5.3 Naming Convention

All references to named entities should include both the name and address, formatted as `name@0xADDRESS`.


## 6. Database Caching

### 6.1 Input File Types

- **IDA databases** (`.i64`, `.idb`): used directly, no analysis needed.
- **Binary files** (PE, ELF, Mach-O, raw, etc.): analyzed by IDA via `idalib`, with the resulting database cached.

### 6.2 Cache Location

Cached databases are stored at:

```
~/.cache/hex-rays/idals/<sha256>.i64
```

Where `<sha256>` is the SHA-256 hex digest of the input binary file.

### 6.3 Cache Behavior

- **Cache hit:** If a cached `.i64` exists for the input file's hash, open it directly. This makes subsequent invocations fast.
- **Cache miss:** Run IDA's auto-analysis on the input file (opening with `-R` so resources are loaded), save the resulting database to the cache location, then proceed.
- **No cache invalidation:** The cache is keyed by content hash, so if the file changes, a new hash produces a new cache entry. Old entries are never automatically deleted (the user can manually clear `~/.cache/hex-rays/idals/`).
- **No concurrency handling:** If two processes analyze the same file simultaneously, behavior is undefined. This is acceptable for the first version.

### 6.4 Analysis Feedback

During initial analysis (cache miss), `idals` should print a brief message to stderr indicating that analysis is in progress:

```
Analyzing malware.exe (this may take a moment)...
```

This message goes to stderr so it doesn't pollute the stdout output that an agent might be parsing.


## 7. Error Handling

### 7.1 File Not Found

```
Error: File not found: /path/to/nonexistent.exe
```

### 7.2 Address Not Found

If the given address doesn't correspond to any mapped content in the database:

```
Error: Address 0xDEADBEEF is not mapped in the binary.

Valid address ranges:
  .text    0x140001000 - 0x140045000
  .rdata   0x140046000 - 0x140052000
  .data    0x140053000 - 0x140055000

Tip: Use `idals malware.exe` (no address) to see the full memory layout.
```

### 7.3 Symbol Not Found

If a symbol name doesn't resolve:

```
Error: Symbol "CreateFlie" not found.

Did you mean:
  CreateFileA  (0x7FF8A0001234)
  CreateFileW  (0x7FF8A0001240)

Tip: Use `idals malware.exe` to see entry points and imports.
```

The "did you mean" suggestions should use simple fuzzy matching (e.g., Levenshtein distance or substring matching) against the database's name list.

### 7.4 IDA/idalib Errors

If `idalib` fails to load, analyze, or open a database, print a clear error to stderr with any available diagnostic information, and exit with a non-zero status code.


## 8. Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | General error (file not found, address not found, etc.) |
| 2 | Usage error (invalid arguments) |
| 3 | IDA/idalib error (license, analysis failure, etc.) |


## 9. Command-Line Interface Summary

```
idals [OPTIONS] [FILE] [ADDRESS]

Positional arguments:
  FILE                Path to binary file or IDA database (.i64/.idb)
  ADDRESS             Virtual address (hex) or symbol name to inspect

Options:
  --after N, -A       Number of instructions/items to show after the target address (default: 16)
  --before N, -B      Number of instructions/items to show before the target address (default: 0)
  --offsets MODE      Addressing mode: va (default), rva, file
  --decompile         Force pseudocode output regardless of length
  --no-decompile      Suppress pseudocode output entirely
  --no-color          Force plain text output even in a TTY
  -h, --help          Show help message (same as no arguments)
  -v, --version       Show version information
```


## 10. Non-Goals (Explicit Exclusions)

To keep the tool focused:

- **No interactive mode.** Every invocation is a single command that produces output and exits.
- **No database modification.** `idals` is read-only. It does not rename functions, add comments, change types, or modify the database in any way.
- **No JSON or structured output.** The output is human/LLM-readable text. Agents parse it as natural language.
- **No batch mode.** One file and one address per invocation. Agents can invoke the tool multiple times.
- **No remote analysis.** The tool runs locally with a local IDA installation.
- **No graph output.** No control flow graphs, call graphs, or visual representations. Text only.


## 11. Packaging and Distribution

`idals` is distributed as a Python package on PyPI under the package name `idals`.

### 11.1 Installation Paths

Supported installation paths are:

- `pip install idals`
- `uv tool install idals`
- `curl -LsSf uvx.sh/idals/install.sh | sh`
- `powershell -ExecutionPolicy ByPass -c "irm https://uvx.sh/idals/install.ps1 | iex"`

### 11.2 Versioning

Published versions use PEP 440 version strings. Pre-release and development builds must use PEP 440-compatible suffixes (for example `0.1.0.dev0`).

### 11.3 Relationship to Runtime Requirements

Package installation does not replace IDA runtime requirements. Users still need a valid `idapro` runtime configuration and access to an IDA installation.
