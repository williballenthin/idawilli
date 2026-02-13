#!/usr/bin/env python3
"""Demonstrate the IDA Sandbox: analyze a binary through a sandboxed script.

The demo opens a binary with IDA Pro (headless/idalib), creates a Monty
sandbox that exposes a handful of IDA analysis primitives, and evaluates a
hard-coded analysis script inside that sandbox.

Usage::

    python demo.py <path-to-executable>
"""

import logging
import sys

from ida_domain import Database
from ida_domain.database import IdaCommandOptions

from ida_codemode_sandbox import IdaSandbox

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# The script below runs *inside* the Monty sandbox and calls codemode APIs.
# ---------------------------------------------------------------------------
SANDBOX_SCRIPT = """\
# --- list all functions ---
functions = get_functions()
print("Found " + str(len(functions)) + " functions:")
for f in functions:
    print("  " + hex(f["address"]) + ": " + f["name"])

# --- choose the first function ---
target = functions[0]
print("")
print("=== Selected: " + target["name"] + " at " + hex(target["address"]) + " ===")

# --- cross-references TO the function ---
xrefs_to = get_xrefs_to_at(target["address"])
print("")
print("Cross-references TO " + target["name"] + ":")
if len(xrefs_to) == 0:
    print("  (none)")
for xref in xrefs_to:
    tag = ""
    if xref["is_call"]:
        tag = " [CALL]"
    if xref["is_jump"]:
        tag = " [JUMP]"
    print("  from " + hex(xref["from_address"]) + " (" + xref["type"] + ")" + tag)

# --- cross-references FROM the function entry ---
xrefs_from = get_xrefs_from_at(target["address"])
print("")
print("Cross-references FROM " + hex(target["address"]) + ":")
if len(xrefs_from) == 0:
    print("  (none)")
for xref in xrefs_from:
    tag = ""
    if xref["is_call"]:
        tag = " [CALL]"
    if xref["is_jump"]:
        tag = " [JUMP]"
    print("  to " + hex(xref["to_address"]) + " (" + xref["type"] + ")" + tag)

# --- disassembly ---
disasm = get_function_disassembly_at(target["address"])
print("")
print("Disassembly of " + target["name"] + ":")
for line in disasm:
    print("  " + line)

# --- raw bytes ---
raw = get_bytes_at(target["address"], 16)
hex_str = ""
for b in raw:
    if b < 16:
        hex_str = hex_str + "0" + hex(b)[2:]
    else:
        hex_str = hex_str + hex(b)[2:]
    hex_str = hex_str + " "
print("")
print("First 16 bytes: " + hex_str)
"""


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path-to-executable>", file=sys.stderr)
        return 1

    binary_path = sys.argv[1]
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    logger.info("Opening %s with IDA Pro...", binary_path)
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=False)

    with Database.open(binary_path, ida_options, save_on_close=False) as db:
        logger.info("Analysis complete.  Creating sandbox...")
        sandbox = IdaSandbox(db, type_check=True)

        logger.info("Evaluating sandbox script...")
        result = sandbox.run(SANDBOX_SCRIPT)

        if result.ok:
            print("".join(result.stdout), end="")
        else:
            print(
                f"Sandbox error ({result.error.kind}):\n"
                f"{result.error.formatted}",
                file=sys.stderr,
            )
            # Still emit any partial output produced before the error.
            if result.stdout:
                print("--- partial output ---")
                print("".join(result.stdout), end="")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
