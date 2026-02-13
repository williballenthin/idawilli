"""Focused tests for ida-codemode-sandbox.

These tests validate sandbox behavior (execution, error handling, limits,
prompt helpers) and smoke-test a small subset of ida-codemode-api callbacks.
Detailed callback semantics are tested in ida-codemode-api.
"""

from __future__ import annotations

from pathlib import Path

import pydantic_monty

from ida_codemode_api import FUNCTION_NAMES, api_reference as codemode_api_reference
from ida_codemode_sandbox import IdaSandbox, SandboxError, SandboxResult


EXPECT_OK_HELPER = """\
def expect_ok(result):
    if "error" in result:
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

    def test_system_prompt_uses_general_wording(self):
        prompt = IdaSandbox.system_prompt()
        assert "analysis and annotation routines" in prompt

    def test_no_local_api_reference_copy(self):
        path = Path("ida_codemode_sandbox/prompts/api_reference.md")
        assert not path.exists()
