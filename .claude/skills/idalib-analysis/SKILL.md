---
name: idalib-analysis
description: Analyze binaries using IDA Pro's Python API (idalib) in headless mode. Use when examining program structure, functions, disassembly, cross-references, or strings without the GUI.
---

# IDA Pro Headless Analysis with idalib

Use this skill to analyze binary files with IDA Pro's Python API (idalib) in headless mode.

## Setup

First, ensure IDA Pro is installed by running:

```bash
$CLAUDE_PROJECT_DIR/.claude/skills/idalib-analysis/scripts/install-ida.sh
```

Wait for the script to complete before proceeding. This may take a few minutes on first run.

## Usage

```python
import idapro
idapro.open_database("path/to/binary", auto_analysis=True)

# Use IDA APIs
import idautils
import idc
import ida_funcs

# Always close when done
idapro.close_database()
```

## Common Tasks

### List all functions
```python
import idapro
idapro.open_database("binary", auto_analysis=True)

import idautils, ida_funcs
for ea in idautils.Functions():
    print(f"{ea:#x}: {ida_funcs.get_func_name(ea)}")

idapro.close_database()
```

### Get disassembly of a function
```python
import idapro
idapro.open_database("binary", auto_analysis=True)

import idautils, idc
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
