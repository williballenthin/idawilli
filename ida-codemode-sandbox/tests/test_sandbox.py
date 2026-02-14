"""High-value tests for ida-codemode-sandbox runtime behavior."""

from __future__ import annotations

import pydantic_monty

from ida_codemode_sandbox import IdaSandbox, SandboxError, SandboxResult


class TestSandboxExecution:
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


class TestSandboxErrors:
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


class TestApiErrorHints:
    def test_first_api_error_prints_help_excerpt_to_stderr(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run("get_function_at(0xDEADDEAD)")

        assert result.ok
        stderr = "".join(result.stderr)
        assert "[api hint] get_function_at returned ApiError:" in stderr
        assert 'help("get_function_at") excerpt (shown once):' in stderr
        assert "get_function_at(address: int)" in stderr

    def test_api_error_hint_printed_once_per_callback(self, db):
        sandbox = IdaSandbox(db)

        first = sandbox.run("get_function_at(0xDEADDEAD)\nget_function_at(0xDEADDEAD)")
        second = sandbox.run("get_function_at(0xDEADDEAD)")

        assert first.ok
        assert second.ok

        first_stderr = "".join(first.stderr)
        second_stderr = "".join(second.stderr)

        assert first_stderr.count('help("get_function_at") excerpt (shown once):') == 1
        assert 'help("get_function_at") excerpt (shown once):' not in second_stderr


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


class TestApiSmokeThroughSandbox:
    def test_read_callback_smoke(self, db):
        sandbox = IdaSandbox(db)
        code = """\
meta = expect_ok(get_database_metadata())
if meta is not None:
    print(meta["architecture"])
"""
        result = sandbox.run(code)
        assert result.ok
        assert "metapc" in "".join(result.stdout)

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


class TestResourceLimits:
    def test_timeout(self, db):
        sandbox = IdaSandbox(
            db,
            limits=pydantic_monty.ResourceLimits(max_duration_secs=0.05),
        )
        result = sandbox.run("x = 0\nwhile True:\n    x = x + 1")
        assert not result.ok
        assert result.error.kind == "runtime"
        assert result.error.inner_type == "TimeoutError"
