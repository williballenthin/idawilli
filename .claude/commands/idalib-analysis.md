# idalib Analysis

Use this skill when analyzing programs with IDA Pro headlessly using idalib.

## Setup

First, ensure IDA Pro is installed by running the installation script:

```bash
$CLAUDE_PROJECT_DIR/.claude/scripts/install-ida.sh
```

Wait for the script to complete before proceeding. This may take a few minutes on first run.

## Usage

Once IDA Pro is installed, you can use idalib to analyze binaries:

```python
import idapro

# Open a database (creates .idb if needed)
idapro.open_database("path/to/binary", auto_analysis=True)

# Now you can use IDA APIs
import idautils
import idc
import ida_funcs
import ida_bytes
import ida_name

# Example: List all functions
for func_ea in idautils.Functions():
    func_name = ida_funcs.get_func_name(func_ea)
    print(f"{func_ea:#x}: {func_name}")

# Close when done
idapro.close_database()
```

## Common Tasks

### Analyze a binary and list functions
```python
import idapro
idapro.open_database("binary", auto_analysis=True)

import idautils
import ida_funcs
for ea in idautils.Functions():
    print(f"{ea:#x}: {ida_funcs.get_func_name(ea)}")

idapro.close_database()
```

### Get disassembly of a function
```python
import idapro
idapro.open_database("binary", auto_analysis=True)

import idautils
import idc
func_ea = idc.get_name_ea_simple("main")
for head in idautils.Heads(func_ea, idc.find_func_end(func_ea)):
    print(f"{head:#x}: {idc.GetDisasm(head)}")

idapro.close_database()
```

### Get cross-references
```python
import idapro
idapro.open_database("binary", auto_analysis=True)

import idautils
for xref in idautils.XrefsTo(target_ea):
    print(f"Referenced from {xref.frm:#x}")

idapro.close_database()
```

## Notes

- Always call `idapro.close_database()` when done
- The `auto_analysis=True` parameter runs IDA's auto-analysis
- Database files (.idb/.i64) are created alongside the binary
- Check `/tmp/claude-idalib.log` for installation/setup issues
