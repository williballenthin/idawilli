"""Tests for the IDA Sandbox.

These tests use mock IDA objects (no IDA Pro required) to verify that:
  1. The sandbox can be created and scripts evaluated.
  2. Each IDA-backed function works correctly through the sandbox boundary.
  3. The full demo script can execute end-to-end.
  4. Resource limits enforce timeouts, memory caps, and recursion depth.
  5. Type checking catches errors before execution.
  6. Structured error handling surfaces runtime, syntax, and typing errors.
"""

import pydantic_monty
import pytest

from ida_sandbox.sandbox import (
    DEFAULT_LIMITS,
    TYPE_STUBS,
    IdaSandbox,
    SandboxError,
    SandboxResult,
    SANDBOX_FUNCTION_NAMES,
    _build_ida_functions,
)


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
# IdaSandbox class — basic operation and SandboxResult
# ---------------------------------------------------------------------------


class TestIdaSandbox:
    """Test the IdaSandbox wrapper end-to-end."""

    def test_create(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        assert sandbox.db is mock_db
        assert set(SANDBOX_FUNCTION_NAMES).issubset(sandbox._fn_impls.keys())

    def test_run_returns_sandbox_result(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("1 + 1")
        assert isinstance(result, SandboxResult)
        assert result.ok is True
        assert result.output == 2
        assert result.error is None

    def test_enumerate_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("len(enumerate_functions())")
        assert result.ok
        assert result.output == 3

    def test_disassemble_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run('lines = disassemble_function(0x401000)\nlen(lines)')
        assert result.ok
        assert result.output == 7

    def test_xrefs_to_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        code = """\
xrefs = get_xrefs_to(0x401100)
xrefs[0]["from_address"]
"""
        result = sandbox.run(code)
        assert result.ok
        assert result.output == 0x401008

    def test_xrefs_from_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        code = """\
xrefs = get_xrefs_from(0x401008)
xrefs[0]["to_address"]
"""
        result = sandbox.run(code)
        assert result.ok
        assert result.output == 0x401100

    def test_read_bytes_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("read_bytes(0x401000, 4)")
        assert result.ok
        assert result.output == [0, 1, 2, 3]

    def test_stdout_capture(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run('print("sandbox says hi")')
        assert result.ok
        assert "sandbox says hi" in "".join(result.stdout)

    def test_print_callback_still_invoked(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        cb_output = []
        result = sandbox.run(
            'print("hello")',
            print_callback=lambda _s, t: cb_output.append(t),
        )
        assert result.ok
        assert "hello" in "".join(cb_output)
        assert "hello" in "".join(result.stdout)


# ---------------------------------------------------------------------------
# Resource limits
# ---------------------------------------------------------------------------


class TestResourceLimits:
    """Verify that resource limits are enforced."""

    def test_default_limits_applied(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        assert sandbox.limits["max_duration_secs"] == 30.0
        assert sandbox.limits["max_memory"] == 100_000_000
        assert sandbox.limits["max_recursion_depth"] == 200

    def test_custom_limits(self, mock_db):
        custom = pydantic_monty.ResourceLimits(max_duration_secs=5.0)
        sandbox = IdaSandbox(mock_db, limits=custom)
        assert sandbox.limits["max_duration_secs"] == 5.0

    def test_timeout_returns_error(self, mock_db):
        sandbox = IdaSandbox(
            mock_db,
            limits=pydantic_monty.ResourceLimits(max_duration_secs=0.05),
        )
        result = sandbox.run("x = 0\nwhile True:\n    x = x + 1")
        assert not result.ok
        assert result.error.kind == "runtime"
        assert result.error.inner_type == "TimeoutError"
        assert "time limit" in result.error.message

    def test_memory_limit_returns_error(self, mock_db):
        sandbox = IdaSandbox(
            mock_db,
            limits=pydantic_monty.ResourceLimits(max_memory=1000),
        )
        result = sandbox.run("x = [0] * 10000000")
        assert not result.ok
        assert result.error.kind == "runtime"
        assert result.error.inner_type == "MemoryError"
        assert "memory limit" in result.error.message

    def test_recursion_limit_returns_error(self, mock_db):
        sandbox = IdaSandbox(
            mock_db,
            limits=pydantic_monty.ResourceLimits(max_recursion_depth=5),
        )
        result = sandbox.run("def f():\n    f()\nf()")
        assert not result.ok
        assert result.error.kind == "runtime"
        assert result.error.inner_type == "RecursionError"

    def test_limits_do_not_block_normal_code(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("sum(range(1000))")
        assert result.ok
        assert result.output == 499500


# ---------------------------------------------------------------------------
# Type checking
# ---------------------------------------------------------------------------


class TestTypeChecking:
    """Verify that opt-in type checking catches errors before execution."""

    def test_type_check_off_by_default(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        assert sandbox.type_check is False

    def test_type_check_passes_valid_code(self, mock_db):
        sandbox = IdaSandbox(mock_db, type_check=True)
        result = sandbox.run("1 + 2")
        assert result.ok
        assert result.output == 3

    def test_type_check_catches_type_error(self, mock_db):
        sandbox = IdaSandbox(mock_db, type_check=True)
        result = sandbox.run('1 + "a"')
        assert not result.ok
        assert result.error.kind == "typing"
        assert "unsupported-operator" in result.error.formatted

    def test_type_check_catches_wrong_arg_type(self, mock_db):
        sandbox = IdaSandbox(mock_db, type_check=True)
        result = sandbox.run('disassemble_function("not_an_int")')
        assert not result.ok
        assert result.error.kind == "typing"
        assert "invalid-argument-type" in result.error.formatted

    def test_type_check_passes_correct_sandbox_calls(self, mock_db):
        sandbox = IdaSandbox(mock_db, type_check=True)
        result = sandbox.run("len(enumerate_functions())")
        assert result.ok
        assert result.output == 3

    def test_type_check_stubs_cover_all_functions(self):
        for name in SANDBOX_FUNCTION_NAMES:
            assert f"def {name}(" in TYPE_STUBS, f"stub missing for {name}"


# ---------------------------------------------------------------------------
# Structured error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Verify that errors are returned as structured SandboxError objects."""

    def test_runtime_error_division_by_zero(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("1 / 0")
        assert not result.ok
        assert result.error.kind == "runtime"
        assert result.error.inner_type == "ZeroDivisionError"
        assert "division by zero" in result.error.message
        assert "Traceback" in result.error.formatted

    def test_runtime_error_name_error(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("undefined_variable")
        assert not result.ok
        assert result.error.kind == "runtime"
        assert result.error.inner_type == "NameError"

    def test_syntax_error(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("if")
        assert not result.ok
        assert result.error.kind == "syntax"
        assert result.error.message  # non-empty

    def test_runtime_error_preserves_partial_stdout(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run('print("before")\n1 / 0')
        assert not result.ok
        assert "before" in "".join(result.stdout)
        assert result.error.kind == "runtime"

    def test_ok_property(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        good = sandbox.run("42")
        bad = sandbox.run("1/0")
        assert good.ok is True
        assert bad.ok is False

    def test_sandbox_error_fields(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("1/0")
        err = result.error
        assert isinstance(err, SandboxError)
        assert isinstance(err.kind, str)
        assert isinstance(err.message, str)
        assert isinstance(err.formatted, str)
        assert isinstance(err.inner_type, str)


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
        result = sandbox.run(self.SCRIPT)
        assert result.ok
        text = "".join(result.stdout)

        assert "Found 3 functions" in text
        assert "Target: helper" in text
        assert "Xrefs to: 1" in text
        assert "[CALL]" in text
        assert "Disassembly lines: 5" in text
        assert "push rbp" in text
        assert "First 4 bytes:" in text

    def test_full_script_with_type_check(self, mock_db):
        sandbox = IdaSandbox(mock_db, type_check=True)
        result = sandbox.run(self.SCRIPT)
        assert result.ok
        text = "".join(result.stdout)
        assert "Found 3 functions" in text
