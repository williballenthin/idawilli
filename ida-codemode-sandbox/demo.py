#!/usr/bin/env python3
"""Demonstrate sandboxed IDA Code Mode execution.

Usage:

    python demo.py <path-to-executable>
"""

import logging
import sys
from pathlib import Path

# Keep local imports available even if ida_domain adjusts sys.path.
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ida_codemode_sandbox import IdaSandbox
from ida_domain import Database
from ida_domain.database import IdaCommandOptions

logger = logging.getLogger(__name__)

SANDBOX_SCRIPT = """\
def expect_ok(result):
    if "error" in result:
        print("API error: " + result["error"])
        return None
    return result

meta = expect_ok(get_database_metadata())
if meta is not None:
    print("Architecture: " + meta["architecture"])
    print("Bitness: " + str(meta["bitness"]))

funcs = expect_ok(get_functions())
if funcs is None:
    print("No function list available.")
else:
    if len(funcs["functions"]) == 0:
        print("No functions discovered.")
    else:
        target = funcs["functions"][0]
        print("")
        print("=== Selected: " + target["name"] + " at " + hex(target["address"]) + " ===")

        xrefs_to = expect_ok(get_xrefs_to_at(target["address"]))
        if xrefs_to is not None:
            print("")
            print("Cross-references TO " + target["name"] + ":")
            if len(xrefs_to["xrefs"]) == 0:
                print("  (none)")
            for xref in xrefs_to["xrefs"]:
                tag = ""
                if xref["is_call"]:
                    tag = " [CALL]"
                if xref["is_jump"]:
                    tag = " [JUMP]"
                print("  from " + hex(xref["from_address"]) + " (" + xref["type"] + ")" + tag)

        disasm = expect_ok(get_function_disassembly_at(target["address"]))
        if disasm is not None:
            print("")
            print("Disassembly:")
            for line in disasm["disassembly"]:
                print("  " + line)

        raw = expect_ok(get_bytes_at(target["address"], 16))
        if raw is not None:
            parts = []
            for b in raw["bytes"]:
                if b < 16:
                    parts.append("0" + hex(b)[2:])
                else:
                    parts.append(hex(b)[2:])
            print("")
            print("First 16 bytes: " + " ".join(parts))
"""


def main() -> int:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path-to-executable>", file=sys.stderr)
        return 1

    binary_path = sys.argv[1]
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    logger.info("Opening %s with IDA Pro...", binary_path)
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=False)

    with Database.open(binary_path, ida_options, save_on_close=False) as db:
        logger.info("Analysis complete. Creating sandbox...")
        sandbox = IdaSandbox(db)

        logger.info("Evaluating sandbox script...")
        result = sandbox.run(SANDBOX_SCRIPT)

        if result.ok:
            print("".join(result.stdout), end="")
            return 0

        print(
            f"Sandbox error ({result.error.kind}):\n"
            f"{result.error.formatted}",
            file=sys.stderr,
        )
        if result.stdout:
            print("--- partial output ---")
            print("".join(result.stdout), end="")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
