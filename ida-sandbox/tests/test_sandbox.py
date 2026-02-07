"""Tests for the IDA Sandbox.

These tests use mock IDA objects (no IDA Pro required) to verify that:
  1. The sandbox can be created and scripts evaluated.
  2. Each IDA-backed function works correctly through the sandbox boundary.
  3. The full demo script can execute end-to-end.
"""

import pydantic_monty
import pytest

from ida_sandbox.sandbox import IdaSandbox, SANDBOX_FUNCTION_NAMES, _build_ida_functions


# ---------------------------------------------------------------------------
# Monty basics (no IDA at all) -- validates our sandbox wiring
# ---------------------------------------------------------------------------


class TestMontyBasics:
    """Verify fundamental Monty sandbox behaviour we rely on."""

    def test_simple_expression(self):
        m = pydantic_monty.Monty("1 + 2")
        assert m.run() == 3

    def test_external_function(self):
        m = pydantic_monty.Monty("add(3, 4)", external_functions=["add"])
        assert m.run(external_functions={"add": lambda x, y: x + y}) == 7

    def test_dict_access(self):
        code = 'd = {"a": 1, "b": 2}\nd["a"] + d["b"]'
        m = pydantic_monty.Monty(code)
        assert m.run() == 3

    def test_print_callback(self):
        output = []
        m = pydantic_monty.Monty('print("hello")')
        m.run(print_callback=lambda _s, t: output.append(t))
        assert "hello" in "".join(output)

    def test_external_returns_list_of_dicts(self):
        code = 'items = get_items()\nitems[0]["name"]'
        m = pydantic_monty.Monty(code, external_functions=["get_items"])
        result = m.run(external_functions={
            "get_items": lambda: [{"name": "alpha"}, {"name": "beta"}],
        })
        assert result == "alpha"


# ---------------------------------------------------------------------------
# IDA function wrappers (via mock db)
# ---------------------------------------------------------------------------


class TestIdaFunctions:
    """Test each IDA-backed function built by _build_ida_functions."""

    def test_enumerate_functions(self, mock_db):
        fns = _build_ida_functions(mock_db)
        result = fns["enumerate_functions"]()
        assert len(result) == 3
        assert result[0] == {"address": 0x401000, "name": "main", "size": 32}
        assert result[1]["name"] == "helper"
        assert result[2]["name"] == "cleanup"

    def test_disassemble_function(self, mock_db):
        fns = _build_ida_functions(mock_db)
        lines = fns["disassemble_function"](0x401000)
        assert "push rbp" in lines
        assert "ret" in lines

    def test_disassemble_unknown_address(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["disassemble_function"](0xDEAD) == []

    def test_get_xrefs_to(self, mock_db):
        fns = _build_ida_functions(mock_db)
        xrefs = fns["get_xrefs_to"](0x401100)
        assert len(xrefs) == 1
        assert xrefs[0]["from_address"] == 0x401008
        assert xrefs[0]["is_call"] is True

    def test_get_xrefs_to_none(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["get_xrefs_to"](0x401000) == []

    def test_get_xrefs_from(self, mock_db):
        fns = _build_ida_functions(mock_db)
        xrefs = fns["get_xrefs_from"](0x401008)
        assert len(xrefs) == 1
        assert xrefs[0]["to_address"] == 0x401100
        assert xrefs[0]["is_call"] is True

    def test_read_bytes(self, mock_db):
        fns = _build_ida_functions(mock_db)
        data = fns["read_bytes"](0x401000, 4)
        assert data == [0, 1, 2, 3]

    def test_read_bytes_invalid_address(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["read_bytes"](0xFFFF, 4) == []

    def test_random_int(self, mock_db):
        fns = _build_ida_functions(mock_db)
        val = fns["random_int"](0, 10)
        assert 0 <= val <= 10


# ---------------------------------------------------------------------------
# IdaSandbox class
# ---------------------------------------------------------------------------


class TestIdaSandbox:
    """Test the IdaSandbox wrapper end-to-end."""

    def test_create(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        assert sandbox.db is mock_db
        assert set(SANDBOX_FUNCTION_NAMES).issubset(sandbox._fn_impls.keys())

    def test_run_simple(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("1 + 1")
        assert result == 2

    def test_enumerate_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("len(enumerate_functions())")
        assert result == 3

    def test_disassemble_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        code = 'lines = disassemble_function(0x401000)\nlen(lines)'
        result = sandbox.run(code)
        assert result == 7  # 7 lines in mock disassembly for main

    def test_xrefs_to_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        code = """\
xrefs = get_xrefs_to(0x401100)
xrefs[0]["from_address"]
"""
        result = sandbox.run(code)
        assert result == 0x401008

    def test_xrefs_from_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        code = """\
xrefs = get_xrefs_from(0x401008)
xrefs[0]["to_address"]
"""
        result = sandbox.run(code)
        assert result == 0x401100

    def test_read_bytes_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        code = "read_bytes(0x401000, 4)"
        result = sandbox.run(code)
        assert result == [0, 1, 2, 3]

    def test_print_capture(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        output = []
        sandbox.run(
            'print("sandbox says hi")',
            print_callback=lambda _s, t: output.append(t),
        )
        assert "sandbox says hi" in "".join(output)


# ---------------------------------------------------------------------------
# Full demo-script smoke test (with mocked data)
# ---------------------------------------------------------------------------


class TestDemoScript:
    """Run a script similar to demo.py's SANDBOX_SCRIPT against the mock db."""

    SCRIPT = """\
functions = enumerate_functions()
print("Found " + str(len(functions)) + " functions")

target = functions[1]
print("Target: " + target["name"])

xrefs = get_xrefs_to(target["address"])
print("Xrefs to: " + str(len(xrefs)))
for xref in xrefs:
    tag = ""
    if xref["is_call"]:
        tag = " [CALL]"
    print("  from " + hex(xref["from_address"]) + tag)

disasm = disassemble_function(target["address"])
print("Disassembly lines: " + str(len(disasm)))
for line in disasm:
    print("  " + line)

raw = read_bytes(target["address"], 4)
print("First 4 bytes: " + str(raw))
"""

    def test_full_script(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        output = []
        sandbox.run(self.SCRIPT, print_callback=lambda _s, t: output.append(t))
        text = "".join(output)

        assert "Found 3 functions" in text
        assert "Target: helper" in text
        assert "Xrefs to: 1" in text
        assert "[CALL]" in text
        assert "Disassembly lines: 5" in text
        assert "push rbp" in text
        assert "First 4 bytes:" in text
