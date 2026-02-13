"""Focused tests for ida-codemode-sandbox.

These tests validate sandbox behavior (execution, error handling, limits,
prompt helpers) and smoke-test a small subset of ida-codemode-api callbacks.
Detailed callback semantics are tested in ida-codemode-api.
"""

from __future__ import annotations

from pathlib import Path

import pydantic_monty
import pytest

from ida_codemode_api import FUNCTION_NAMES, api_reference as codemode_api_reference
from ida_codemode_sandbox import IdaSandbox, SandboxError, SandboxResult


EXPECT_OK_HELPER = """\
def expect_ok(result):
    if is_error(result):
        print("API error: " + result["error"])
        return None
    return result
"""


class TestMontyBasics:
    def test_simple_expression(self):
        m = pydantic_monty.Monty("1 + 2")
        assert m.run() == 3

    def test_external_function(self):
        m = pydantic_monty.Monty("add(3, 4)", external_functions=["add"])
        assert m.run(external_functions={"add": lambda x, y: x + y}) == 7

    def test_print_callback(self):
        output = []
        m = pydantic_monty.Monty('print("hello")')
        m.run(print_callback=lambda _s, t: output.append(t))
        assert "hello" in "".join(output)


class TestSandboxExecution:
    def test_create(self, db):
        sandbox = IdaSandbox(db)
        assert sandbox.db is db
        assert set(FUNCTION_NAMES).issubset(sandbox._fn_impls.keys())
        assert "is_error" in sandbox._fn_impls

    def test_run_returns_structured_result(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run("1 + 1")
        assert isinstance(result, SandboxResult)
        assert result.ok
        assert result.output == 2
        assert result.error is None

    def test_stdout_capture(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run('print("sandbox says hi")')
        assert result.ok
        assert "sandbox says hi" in "".join(result.stdout)

    def test_print_callback(self, db):
        sandbox = IdaSandbox(db)
        captured = []
        result = sandbox.run('print("hello")', print_callback=lambda _s, t: captured.append(t))
        assert result.ok
        assert "hello" in "".join(result.stdout)
        assert "hello" in "".join(captured)


class TestSandboxErrors:
    def test_syntax_error(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run("if")
        assert not result.ok
        assert result.error.kind == "syntax"

    def test_typing_error(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run("get_functions(1)")
        assert not result.ok
        assert result.error.kind == "typing"

    def test_runtime_error(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run("1 / 0")
        assert not result.ok
        assert result.error.kind == "runtime"
        assert result.error.inner_type == "ZeroDivisionError"
        assert isinstance(result.error, SandboxError)

    def test_preserves_partial_stdout(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run('print("before")\n1 / 0')
        assert not result.ok
        assert result.error.kind == "runtime"
        assert "before" in "".join(result.stdout)


class TestTypedDictNarrowingRegression:
    def test_direct_error_key_check_reproduces_typing_failure(self, db):
        sandbox = IdaSandbox(db)
        code = """\
meta = get_database_metadata()
if "error" in meta:
    print(meta["error"])
else:
    print("Entry: " + hex(meta["entry_point"]))

funcs = get_functions()
if "error" in funcs:
    print(funcs["error"])
else:
    print("Count: " + str(len(funcs["functions"])))
"""
        result = sandbox.run(code)

        assert not result.ok
        assert result.error is not None
        assert result.error.kind == "typing"
        assert 'Unknown key "error"' in result.error.formatted
        assert "DatabaseMetadata" in result.error.formatted
        assert "GetFunctionsOk" in result.error.formatted

    def test_type_guard_helper_supports_union_error_checks(self, db):
        sandbox = IdaSandbox(db)
        code = """\
meta = get_database_metadata()
if is_error(meta):
    print(meta["error"])
else:
    print("Entry: " + hex(meta["entry_point"]))

funcs = get_functions()
if is_error(funcs):
    print(funcs["error"])
else:
    print("Count: " + str(len(funcs["functions"])))
"""
        result = sandbox.run(code)

        assert result.ok
        out = "".join(result.stdout)
        assert "Entry:" in out
        assert "Count:" in out


class TestTypeCheckerAlternatives:
    def test_union_plus_error_key_check_fails_without_type_guard(self):
        stubs = """\
from typing import TypedDict

class ApiError(TypedDict):
    error: str

class ValueOk(TypedDict):
    value: int

def get_value() -> ValueOk | ApiError:
    raise NotImplementedError
"""

        code = """\
result = get_value()
if "error" in result:
    print(result["error"])
else:
    print(result["value"])
"""

        with pytest.raises(pydantic_monty.MontyTypingError) as excinfo:
            pydantic_monty.Monty(
                code,
                external_functions=["get_value"],
                type_check=True,
                type_check_stubs=stubs,
            )

        assert 'Unknown key "error"' in excinfo.value.display(format="full")

    def test_union_plus_typeis_guard_succeeds(self):
        stubs = """\
from typing import TypedDict
from typing_extensions import TypeIs

class ApiError(TypedDict):
    error: str

class ValueOk(TypedDict):
    value: int

def get_value() -> ValueOk | ApiError:
    raise NotImplementedError

def is_error(result: object) -> TypeIs[ApiError]:
    raise NotImplementedError
"""

        code = """\
result = get_value()
if is_error(result):
    print(result["error"])
else:
    print(result["value"])
"""

        m = pydantic_monty.Monty(
            code,
            external_functions=["get_value", "is_error"],
            type_check=True,
            type_check_stubs=stubs,
        )
        out = []
        m.run(
            external_functions={
                "get_value": lambda: {"value": 7},
                "is_error": lambda result: isinstance(result, dict) and "error" in result,
            },
            print_callback=lambda _s, t: out.append(t),
        )

        assert "7" in "".join(out)

    def test_single_merged_total_false_result_type_succeeds(self):
        stubs = """\
from typing import TypedDict

class ValueResult(TypedDict, total=False):
    value: int
    error: str

def get_value() -> ValueResult:
    raise NotImplementedError
"""

        code = """\
result = get_value()
if "error" in result:
    print(result["error"])
else:
    print(result["value"])
"""

        m = pydantic_monty.Monty(
            code,
            external_functions=["get_value"],
            type_check=True,
            type_check_stubs=stubs,
        )
        out = []
        m.run(
            external_functions={"get_value": lambda: {"value": 7}},
            print_callback=lambda _s, t: out.append(t),
        )

        assert "7" in "".join(out)


class TestApiSmokeThroughSandbox:
    def test_read_callback_smoke(self, db):
        sandbox = IdaSandbox(db)
        code = EXPECT_OK_HELPER + """\
meta = expect_ok(get_database_metadata())
if meta is not None:
    print(meta["architecture"])
"""
        result = sandbox.run(code)
        assert result.ok
        assert "metapc" in "".join(result.stdout)

    def test_second_read_callback_smoke(self, db):
        sandbox = IdaSandbox(db)
        code = EXPECT_OK_HELPER + """\
funcs = expect_ok(get_functions())
if funcs is not None:
    print(str(len(funcs["functions"])))
"""
        result = sandbox.run(code)
        assert result.ok
        out = "".join(result.stdout).strip()
        assert out
        assert int(out) >= 1

    def test_mutation_callback_is_available(self, db):
        sandbox = IdaSandbox(db)
        code = """\
result = set_comment_at(0xDEADDEAD, "sandbox smoke")
if result is None:
    print("mutation succeeded")
elif "error" in result:
    print("mutation error")
"""
        result = sandbox.run(code)
        assert result.ok
        assert "mutation" in "".join(result.stdout)


class TestExecuteAdapter:
    def test_success_returns_stdout(self, db):
        sandbox = IdaSandbox(db)
        output = sandbox.execute('print("hello")')
        assert "hello" in output

    def test_error_returns_description(self, db):
        sandbox = IdaSandbox(db)
        output = sandbox.execute("1 / 0")
        assert "Script error" in output
        assert "runtime" in output

    def test_can_run_api_script(self, db):
        sandbox = IdaSandbox(db)
        output = sandbox.execute(
            EXPECT_OK_HELPER
            + 'meta = expect_ok(get_database_metadata())\n'
            + 'if meta is not None:\n'
            + '    print(meta["architecture"])\n'
        )
        assert "metapc" in output


class TestResourceLimits:
    def test_default_limits(self, db):
        sandbox = IdaSandbox(db)
        assert sandbox.limits["max_duration_secs"] == 30.0
        assert sandbox.limits["max_memory"] == 100_000_000
        assert sandbox.limits["max_recursion_depth"] == 200

    def test_custom_limits(self, db):
        custom = pydantic_monty.ResourceLimits(max_duration_secs=5.0)
        sandbox = IdaSandbox(db, limits=custom)
        assert sandbox.limits["max_duration_secs"] == 5.0

    def test_timeout(self, db):
        sandbox = IdaSandbox(
            db,
            limits=pydantic_monty.ResourceLimits(max_duration_secs=0.05),
        )
        result = sandbox.run("x = 0\nwhile True:\n    x = x + 1")
        assert not result.ok
        assert result.error.kind == "runtime"
        assert result.error.inner_type == "TimeoutError"


class TestPromptHelpers:
    def test_api_reference_is_forwarded_from_api_module(self):
        assert IdaSandbox.api_reference() == codemode_api_reference()

    def test_system_prompt_includes_dynamic_reference(self):
        prompt = IdaSandbox.system_prompt()
        assert "get_database_metadata" in prompt
        assert "set_comment_at" in prompt
        assert "is_error" in prompt

    def test_system_prompt_uses_general_wording(self):
        prompt = IdaSandbox.system_prompt()
        assert "analysis and annotation routines" in prompt

    def test_no_local_api_reference_copy(self):
        path = Path("ida_codemode_sandbox/prompts/api_reference.md")
        assert not path.exists()
