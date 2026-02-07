# ida-codemode-sandbox

A secure Python sandbox for IDA Pro binary analysis, built on
[pydantic-monty](https://github.com/pydantic/monty).

Sandboxed scripts can call 28 IDA analysis functions but cannot access
the filesystem, network, or host process.  This makes it safe to run
AI-generated or untrusted analysis code against a real IDA database.


## Quick start

```python
from ida_domain import Database
from ida_domain.database import IdaCommandOptions
from ida_codemode_sandbox import IdaSandbox

ida_opts = IdaCommandOptions(auto_analysis=True, new_database=False)
with Database.open("sample.exe", ida_opts, save_on_close=False) as db:
    sandbox = IdaSandbox(db, type_check=True)
    result = sandbox.run(SCRIPT)

    if result.ok:
        print("".join(result.stdout))
    else:
        print(f"error: {result.error.formatted}")
```


## Writing sandbox scripts

Scripts run inside [Monty](https://github.com/pydantic/monty), a
sandboxed Python subset interpreter.  The 28 analysis functions listed
below are pre-loaded as globals — just call them.

### Language subset

Monty supports core Python: variables, `if`/`elif`/`else`, `for`/`while`,
`def`, `class`, `list`/`dict`/`tuple`/`set` literals, list comprehensions,
f-strings, `try`/`except`, and common builtins (`len`, `range`, `str`,
`int`, `hex`, `print`, `sorted`, `enumerate`, `zip`, `isinstance`, …).

**Not available**: `import`, `open()`, `eval()`, `exec()`, `__import__`,
`os`, `sys`, `subprocess`, or any I/O.  This is by design.

### Data model

Every function returns plain Python values — `dict`, `list`, `str`,
`int`, `bool`, or `None`.  IDA domain objects are serialized at the
boundary so scripts never hold opaque references.

Dicts use string keys.  A function descriptor, for example, is always:
```python
{"address": 0x401000, "name": "main", "size": 42}
```

### Patterns and examples

#### Enumerate and filter

```python
# Find all functions larger than 1 KB
functions = enumerate_functions()
large = []
for f in functions:
    if f["size"] > 1024:
        large.append(f)
print("Large functions: " + str(len(large)))
for f in large:
    print("  " + f["name"] + " (" + str(f["size"]) + " bytes)")
```

#### Look up a function by name, then analyze it

```python
fn = get_function_by_name("main")
if fn is not None:
    sig = get_function_signature(fn["address"])
    print("Signature: " + str(sig))

    callees = get_callees(fn["address"])
    print("Calls " + str(len(callees)) + " functions:")
    for c in callees:
        print("  " + c["name"])

    blocks = get_basic_blocks(fn["address"])
    print("Basic blocks: " + str(len(blocks)))
```

#### Walk the call graph

```python
# Find functions called by main that also have callers beyond main
main = get_function_by_name("main")
if main is not None:
    for callee in get_callees(main["address"]):
        callers = get_callers(callee["address"])
        if len(callers) > 1:
            names = []
            for c in callers:
                names.append(c["name"])
            print(callee["name"] + " also called by: " + str(names))
```

#### Cross-reference analysis

```python
# For every string that mentions "password", show who references it
strings = enumerate_strings()
for s in strings:
    if "password" in s["value"].lower():
        print(s["value"])
        xrefs = get_xrefs_to(s["address"])
        for x in xrefs:
            name = get_name_at(x["from_address"])
            print("  ref from " + hex(x["from_address"]) + " " + str(name))
```

#### Disassembly and bytes

```python
fn = get_function_by_name("main")
if fn is not None:
    # Full function disassembly
    for line in disassemble_function(fn["address"]):
        print(line)

    # Single instruction at entry
    insn = get_instruction_at(fn["address"])
    if insn is not None:
        print(insn["mnemonic"] + " (size=" + str(insn["size"]) + ")")

    # Raw bytes
    raw = read_bytes(fn["address"], 8)
    parts = []
    for b in raw:
        if b < 16:
            parts.append("0" + hex(b)[2:])
        else:
            parts.append(hex(b)[2:])
    print(" ".join(parts))
```

#### Search for a byte pattern

```python
# Find all locations of "push ebp; mov ebp, esp" (x86 prologue)
hits = find_bytes([0x55, 0x8B, 0xEC])
print("Found prologue at " + str(len(hits)) + " locations")
for addr in hits:
    name = get_name_at(addr)
    if name is not None:
        print("  " + hex(addr) + " " + name)
```

#### Imports and entry points

```python
imports = enumerate_imports()
print("Imports: " + str(len(imports)))
for imp in imports:
    print("  " + imp["module"] + "!" + imp["name"])

entries = enumerate_entries()
for e in entries:
    print("Entry: " + e["name"] + " at " + hex(e["address"]))
```

#### Binary metadata

```python
info = get_binary_info()
print(info["module"] + " (" + info["architecture"] + ", " + str(info["bitness"]) + "-bit)")
print("Format: " + info["format"])
print("MD5:    " + info["md5"])
```

#### Address classification

```python
functions = enumerate_functions()
for f in functions:
    addr = f["address"]
    parts = [f["name"]]
    if is_code_at(addr):
        parts.append("CODE")
    comment = get_comment_at(addr)
    if comment is not None:
        parts.append('"' + comment + '"')
    print("  ".join(parts))
```


## Function reference

### Database metadata

| Function | Returns | Description |
|----------|---------|-------------|
| `get_binary_info()` | `dict` | path, module, architecture, bitness, format, base_address, entry_point, minimum_ea, maximum_ea, filesize, md5, sha256, crc32 |

### Functions

| Function | Returns | Description |
|----------|---------|-------------|
| `enumerate_functions()` | `list[dict]` | All functions: `{address, name, size}` |
| `get_function_by_name(name)` | `dict \| None` | Look up by exact name |
| `disassemble_function(address)` | `list[str]` | Disassembly lines |
| `decompile_function(address)` | `list[str]` | C pseudocode (needs Hex-Rays) |
| `get_function_signature(address)` | `str \| None` | C-style type signature |
| `get_callers(address)` | `list[dict]` | Functions that call this one: `{address, name}` |
| `get_callees(address)` | `list[dict]` | Functions this one calls: `{address, name}` |
| `get_basic_blocks(address)` | `list[dict]` | CFG: `{start, end, successors, predecessors}` |

### Cross-references

| Function | Returns | Description |
|----------|---------|-------------|
| `get_xrefs_to(address)` | `list[dict]` | Refs targeting address: `{from_address, type, is_call, is_jump}` |
| `get_xrefs_from(address)` | `list[dict]` | Refs originating at address: `{to_address, type, is_call, is_jump}` |

### Strings

| Function | Returns | Description |
|----------|---------|-------------|
| `enumerate_strings()` | `list[dict]` | All strings: `{address, length, type, value}` |
| `get_string_at(address)` | `str \| None` | Read null-terminated C string |

### Segments

| Function | Returns | Description |
|----------|---------|-------------|
| `enumerate_segments()` | `list[dict]` | All segments: `{name, start, end, size, permissions, class, bitness}` |

### Names / symbols

| Function | Returns | Description |
|----------|---------|-------------|
| `enumerate_names()` | `list[dict]` | All named addresses: `{address, name}` |
| `get_name_at(address)` | `str \| None` | Symbol name at address |
| `demangle_name(name)` | `str` | Demangle C++ name (pass-through if not mangled) |

### Imports and entries

| Function | Returns | Description |
|----------|---------|-------------|
| `enumerate_imports()` | `list[dict]` | All imports: `{address, name, module, ordinal}` |
| `enumerate_entries()` | `list[dict]` | All entry points: `{ordinal, address, name, forwarder}` |

### Bytes / memory

| Function | Returns | Description |
|----------|---------|-------------|
| `read_bytes(address, size)` | `list[int]` | Raw byte values (0-255) |
| `find_bytes(pattern)` | `list[int]` | Addresses matching byte pattern |
| `get_disassembly_at(address)` | `str \| None` | Single instruction disassembly |
| `get_instruction_at(address)` | `dict \| None` | `{address, size, mnemonic, disassembly, is_call}` |

### Address classification

| Function | Returns | Description |
|----------|---------|-------------|
| `is_code_at(address)` | `bool` | Address contains code |
| `is_data_at(address)` | `bool` | Address contains defined data |
| `is_valid_address(address)` | `bool` | Address is mapped |

### Comments

| Function | Returns | Description |
|----------|---------|-------------|
| `get_comment_at(address)` | `str \| None` | Analyst comment at address |

### Utilities

| Function | Returns | Description |
|----------|---------|-------------|
| `random_int(low, high)` | `int` | Random integer in `[low, high]` |


## Tips

- **Unmapped addresses return empty results**, not errors.
  `disassemble_function(0xDEAD)` returns `[]`, `get_name_at(0xDEAD)` returns `None`.
- **`decompile_function` requires a Hex-Rays license.**
  It returns `[]` gracefully when the decompiler is unavailable.
- **String concatenation, not f-strings for print.**
  While Monty supports f-strings, `print("x = " + str(val))` is the
  most portable pattern.
- **`find_bytes` takes `list[int]`, not `bytes`.**
  Monty's Python subset does not have a `bytes` literal, so patterns
  are expressed as lists of integers.
- **Use `enumerate_*` then filter**, rather than trying to guess addresses.
  Discover addresses dynamically from the API rather than hardcoding them.
- **Keep scripts focused.**
  Write small scripts that answer a specific question, then iterate.
  The 30-second timeout is generous for focused queries but will cut
  off scripts that try to dump everything.


## Resource limits

| Limit | Default |
|-------|---------|
| Timeout | 30 seconds |
| Memory | 100 MB |
| Recursion depth | 200 frames |

Override at construction:

```python
import pydantic_monty

sandbox = IdaSandbox(db, limits=pydantic_monty.ResourceLimits(
    max_duration_secs=60.0,
    max_memory=200_000_000,
))
```


## Type checking

Enable static type checking to catch errors before execution:

```python
sandbox = IdaSandbox(db, type_check=True)
result = sandbox.run('disassemble_function("wrong")')
# result.ok == False
# result.error.kind == "typing"
```


## Structured results

`sandbox.run()` returns a `SandboxResult`:

```python
result = sandbox.run(script)

result.ok        # True if no error
result.output    # value of the last expression
result.stdout    # list of printed lines
result.stderr    # list of stderr lines
result.error     # SandboxError or None

# On error:
result.error.kind       # "runtime", "syntax", or "typing"
result.error.message    # short description
result.error.formatted  # full traceback / details
result.error.inner_type # e.g. "ZeroDivisionError"
```


## Running tests

```bash
python -m pytest ida-codemode-sandbox/tests/ -v
```

Tests run against real IDA Pro analysis of the shared test binary
(`tests/data/Practical Malware Analysis Lab 01-01.exe_`).
No mocks.
