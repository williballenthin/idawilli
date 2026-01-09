---
name: idalib-analysis
description: Analyze binaries using IDA Pro's Python API (idalib) in headless mode. Use when examining program structure, functions, disassembly, cross-references, or strings without the GUI.
---

# IDA Pro Headless Analysis with idalib

Use this skill to analyze binary files with IDA Pro's Python API in headless mode.

## Setup

First, ensure IDA Pro is installed by running:

```bash
$CLAUDE_PROJECT_DIR/.claude/skills/idalib-analysis/scripts/install-ida.sh
```

Wait for the script to complete before proceeding. This may take a few minutes on first run.

## Use the IDA Domain API

**Always prefer the IDA Domain API** over the legacy low-level IDA Python SDK. The Domain API provides a clean, Pythonic interface that is easier to use and understand.

### Documentation Resources

| Resource | URL |
|----------|-----|
| **LLM-optimized overview** | https://ida-domain.docs.hex-rays.com/llms.txt |
| **Getting Started** | https://ida-domain.docs.hex-rays.com/getting_started/index.md |
| **Examples** | https://ida-domain.docs.hex-rays.com/examples/index.md |
| **API Reference** | https://ida-domain.docs.hex-rays.com/ref/{module}/index.md |

Available API modules: `bytes`, `comments`, `database`, `entries`, `flowchart`, `functions`, `heads`, `hooks`, `instructions`, `names`, `operands`, `segments`, `signature_files`, `strings`, `types`, `xrefs`

**To fetch specific API documentation**, use URLs like:
- `https://ida-domain.docs.hex-rays.com/ref/functions/index.md` - Function analysis API
- `https://ida-domain.docs.hex-rays.com/ref/xrefs/index.md` - Cross-reference API
- `https://ida-domain.docs.hex-rays.com/ref/strings/index.md` - String analysis API

### Opening a Database

```python
from ida_domain import Database
from ida_domain.database import IdaCommandOptions

# Open with auto-analysis enabled and save database for faster subsequent runs
ida_options = IdaCommandOptions(auto_analysis=True, new_database=False)
with Database.open("path/to/binary", ida_options, save_on_close=True) as db:
    # Your analysis here
    pass
# Database is automatically closed and saved
```

### Key Database Properties

```python
with Database.open(path, ida_options) as db:
    db.minimum_ea      # Start address
    db.maximum_ea      # End address
    db.metadata        # Database metadata
    db.architecture    # Target architecture

    db.functions       # All functions (iterable)
    db.strings         # All strings (iterable)
    db.segments        # Memory segments
    db.names           # Symbols and labels
    db.entries         # Entry points
    db.types           # Type definitions
    db.comments        # All comments
    db.xrefs           # Cross-reference utilities
    db.bytes           # Byte manipulation
    db.instructions    # Instruction access
```

### Common Analysis Tasks

**List functions:**
```python
for func in db.functions:
    name = db.functions.get_name(func)
    print(f"{hex(func.start_ea)}: {name} ({func.size} bytes)")
```

**Get function disassembly and pseudocode:**
```python
func = next(f for f in db.functions if db.functions.get_name(f) == "main")
for line in db.functions.get_disassembly(func):
    print(line)

# Pseudocode requires Hex-Rays decompiler license - handle gracefully
try:
    for line in db.functions.get_pseudocode(func):
        print(line)
except RuntimeError as e:
    print(f"Decompilation unavailable: {e}")
```

**Find strings:**
```python
for s in db.strings:
    print(f"{hex(s.address)}: {s}")
```

**Cross-references:**
```python
# References TO an address
for xref in db.xrefs.to_ea(target_addr):
    print(f"Referenced from {hex(xref.from_ea)} (type: {xref.type.name})")

# References FROM an address
for xref in db.xrefs.from_ea(source_addr):
    print(f"References {hex(xref.to_ea)}")

# Specific xref types
for xref in db.xrefs.calls_to_ea(func_addr):
    print(f"Called from {hex(xref.from_ea)}")
```

**Read bytes:**
```python
byte_val = db.bytes.get_byte_at(addr)
dword_val = db.bytes.get_dword_at(addr)
disasm = db.bytes.get_disassembly_at(addr)
```

## Analysis Methodology

**Write and execute small, focused scripts** rather than reading large amounts of data from the binary. This approach is more efficient and produces better results:

1. **Form a hypothesis** about what you're looking for
2. **Design a script** to gather the minimum data needed to test the hypothesis
3. **Execute the script** and analyze the results
4. **Iterate** based on findings

### Example: Investigating a suspicious function

Instead of dumping all disassembly, write targeted scripts:

```python
# Script 1: Find functions that reference interesting strings
from ida_domain import Database
from ida_domain.database import IdaCommandOptions

ida_options = IdaCommandOptions(auto_analysis=True, new_database=False)
with Database.open("sample.exe", ida_options, save_on_close=True) as db:
    for s in db.strings:
        if "password" in str(s).lower():
            print(f"\nString at {hex(s.address)}: {s}")
            for xref in db.xrefs.to_ea(s.address):
                print(f"  Referenced from {hex(xref.from_ea)}")
```

```python
# Script 2: Analyze a specific function found in Script 1
with Database.open("sample.exe", ida_options, save_on_close=True) as db:
    target_addr = 0x401234  # Address from previous script
    for func in db.functions:
        if func.start_ea <= target_addr < func.end_ea:
            print(f"Function: {db.functions.get_name(func)}")
            print(f"Signature: {db.functions.get_signature(func)}")

            # Try pseudocode first (requires Hex-Rays license)
            try:
                print("\nPseudocode:")
                for line in db.functions.get_pseudocode(func):
                    print(f"  {line}")
            except RuntimeError:
                # Fall back to disassembly if decompiler unavailable
                print("\nDisassembly (decompiler unavailable):")
                for line in db.functions.get_disassembly(func):
                    print(f"  {line}")
            break
```

## Performance Tips

1. **Enable auto_analysis=True** on first open to let IDA analyze the binary
2. **Use save_on_close=True** to persist the analysis database (.idb/.i64)
3. **Subsequent opens are faster** because analysis results are cached in the .idb
4. **Write focused scripts** that gather specific data rather than iterating over everything

## Troubleshooting

- Check `/tmp/claude-idalib.log` for installation and setup issues
- Database files (.idb/.i64) are created alongside the binary
- If imports fail, verify IDA Pro is installed and IDADIR is set

### Decompilation Not Working

**Pseudocode/decompilation requires a Hex-Rays decompiler license**, which is separate from the IDA Pro base license. If `get_pseudocode()` or `get_microcode()` fails with `RuntimeError`, check the license status:

```python
import ida_hexrays

# Check if decompiler is available
def is_decompiler_available():
    """Check if Hex-Rays decompiler is licensed and available."""
    if not ida_hexrays.init_hexrays_plugin():
        return False

    # Try a test decompilation - MERR_LICENSE (-23) means no license
    import ida_funcs
    for func_ea in range(db.minimum_ea, db.maximum_ea):
        func = ida_funcs.get_func(func_ea)
        if func:
            hf = ida_hexrays.hexrays_failure_t()
            cfunc = ida_hexrays.decompile(func.start_ea, hf)
            if cfunc:
                return True
            # Error code -23 is MERR_LICENSE
            if hf.code == -23:
                return False
            break
    return False
```

**Error codes reference:**
- `MERR_LICENSE (-23)`: No valid Hex-Rays decompiler license
- `MERR_ONLY32 (-24)`: 32-bit decompiler not available (need hexx86 plugin)
- `MERR_ONLY64 (-25)`: 64-bit decompiler not available (need hexx64 plugin)

**Workaround when decompilation is unavailable:** Use disassembly analysis instead - the `get_disassembly()` method always works and provides assembly-level insight.

## Exploring the API at Runtime

When the documentation doesn't answer your question, explore the API directly:

```python
import inspect
from ida_domain import Database
from ida_domain.functions import Functions

# List all public methods on a class
for name, method in inspect.getmembers(Functions, predicate=inspect.isfunction):
    if not name.startswith('_'):
        print(f"{name}: {inspect.signature(method)}")

# Get docstring for a specific method
print(Functions.get_pseudocode.__doc__)

# Within a database context, explore available attributes
with Database.open(path, ida_options) as db:
    # List all database properties
    print([attr for attr in dir(db) if not attr.startswith('_')])
```

## Legacy API (Avoid)

The legacy `idc`, `idautils`, `ida_funcs` APIs still work but are harder to use. **Prefer the Domain API** for new analysis scripts. Only use legacy APIs when Domain API doesn't expose needed functionality.
