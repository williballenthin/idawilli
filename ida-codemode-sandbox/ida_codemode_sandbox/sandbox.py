"""IDA Sandbox: a Monty-based sandbox exposing IDA Pro analysis routines.

Creates a secure execution environment where sandboxed Python code can call
a curated set of IDA Pro analysis functions backed by ``ida_codemode_api``.
Every function serializes IDA objects into plain Python primitives (dicts,
lists, ints, strings) so they can safely cross the sandbox boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import pydantic_monty
from ida_codemode_api import (
    FUNCTION_NAMES,
    TYPE_STUBS,
    build_ida_functions,
)

_PROMPTS_DIR = Path(__file__).parent / "prompts"


# ---------------------------------------------------------------------------
# Structured result and error types
# ---------------------------------------------------------------------------


@dataclass
class SandboxError:
    """Structured representation of an error raised during sandbox execution.

    Example::

        result = sandbox.run("1 / 0")
        if not result.ok:
            err = result.error
            print(err.kind)        # "runtime"
            print(err.inner_type)  # "ZeroDivisionError"
            print(err.formatted)   # full traceback
    """

    kind: str
    """One of ``"runtime"``, ``"syntax"``, ``"typing"``."""

    message: str
    """Human-readable error message."""

    formatted: str
    """Richly formatted error string (traceback for runtime, full for typing)."""

    inner_type: str | None = None
    """Name of the inner Python exception (e.g. ``"ZeroDivisionError"``)."""


@dataclass
class SandboxResult:
    """Structured return value from :meth:`IdaSandbox.run`.

    Example::

        result = sandbox.run('print("hello")')
        if result.ok:
            print("".join(result.stdout))  # "hello\\n"
        else:
            print(result.error.formatted)
    """

    output: object = None
    """The value of the last expression in the evaluated code."""

    stdout: list[str] = field(default_factory=list)
    """Lines printed to stdout by the sandboxed code."""

    stderr: list[str] = field(default_factory=list)
    """Lines printed to stderr by the sandboxed code."""

    error: SandboxError | None = None
    """If the sandbox script failed, details about the error."""

    @property
    def ok(self) -> bool:
        """``True`` when the script completed without error."""
        return self.error is None


# ---------------------------------------------------------------------------
# Default resource limits
# ---------------------------------------------------------------------------

DEFAULT_LIMITS = pydantic_monty.ResourceLimits(
    max_duration_secs=30.0,
    max_memory=100_000_000,    # 100 MB
    max_recursion_depth=200,
)


# ---------------------------------------------------------------------------
# Error conversion helpers
# ---------------------------------------------------------------------------


def _runtime_error_to_sandbox_error(exc: pydantic_monty.MontyRuntimeError) -> SandboxError:
    inner = exc.exception()
    return SandboxError(
        kind="runtime",
        message=exc.display(format="msg"),
        formatted=exc.display(format="traceback"),
        inner_type=type(inner).__name__,
    )


def _syntax_error_to_sandbox_error(exc: pydantic_monty.MontySyntaxError) -> SandboxError:
    return SandboxError(
        kind="syntax",
        message=str(exc),
        formatted=str(exc),
    )


def _typing_error_to_sandbox_error(exc: pydantic_monty.MontyTypingError) -> SandboxError:
    return SandboxError(
        kind="typing",
        message=str(exc),
        formatted=exc.display(format="full"),
    )


# ---------------------------------------------------------------------------
# IdaSandbox
# ---------------------------------------------------------------------------


class IdaSandbox:
    """A Monty sandbox with IDA Pro analysis routines exposed.

    Usage::

        from ida_domain import Database
        from ida_codemode_sandbox import IdaSandbox

        with Database.open(path, options) as db:
            sandbox = IdaSandbox(db)
            result = sandbox.run(code)
            if result.ok:
                print("".join(result.stdout))
            else:
                print(result.error.formatted)

    Args:
        db: An open ``ida_domain.Database`` instance.
        limits: Optional ``pydantic_monty.ResourceLimits`` overriding the
            defaults (30 s wall-clock, 100 MB memory, 200 recursion depth).
        type_check: When ``True``, scripts are statically type-checked at
            construction time and again on every :meth:`run` call.  Type
            errors are returned as ``SandboxResult.error`` with
            ``kind="typing"`` instead of raising.
    """

    def __init__(
        self,
        db: Any,
        *,
        limits: pydantic_monty.ResourceLimits | None = None,
        type_check: bool = False,
    ):
        self.db = db
        self.limits = limits if limits is not None else dict(DEFAULT_LIMITS)
        self.type_check = type_check
        self._fn_impls = build_ida_functions(db)

    def run(self, code: str, print_callback: Callable[[str, str], None] | None = None) -> SandboxResult:
        """Evaluate *code* in the sandbox.

        Args:
            code: Python source code to evaluate inside the sandbox.
            print_callback: Optional ``(stream, text)`` callback for captured
                ``print()`` output.  If supplied, it is called *in addition
                to* the result's ``stdout``/``stderr`` lists.

        Returns:
            A :class:`SandboxResult` with the script output, captured prints,
            and any error that occurred.

        Example::

            result = sandbox.run('functions = enumerate_functions()\\n'
                                 'print("count: " + str(len(functions)))')
            if result.ok:
                print("".join(result.stdout))
        """
        stdout: list[str] = []
        stderr: list[str] = []

        def _capture(stream: str, text: str) -> None:
            if stream == "stderr":
                stderr.append(text)
            else:
                stdout.append(text)
            if print_callback is not None:
                print_callback(stream, text)

        # --- Construct the Monty instance (syntax + type errors surface here)
        try:
            m = pydantic_monty.Monty(
                code,
                external_functions=FUNCTION_NAMES,
                type_check=self.type_check,
                type_check_stubs=TYPE_STUBS if self.type_check else None,
            )
        except pydantic_monty.MontySyntaxError as exc:
            return SandboxResult(error=_syntax_error_to_sandbox_error(exc))
        except pydantic_monty.MontyTypingError as exc:
            return SandboxResult(error=_typing_error_to_sandbox_error(exc))

        # --- Execute
        try:
            output = m.run(
                external_functions=self._fn_impls,
                print_callback=_capture,
                limits=self.limits,
            )
        except pydantic_monty.MontyRuntimeError as exc:
            return SandboxResult(
                stdout=stdout,
                stderr=stderr,
                error=_runtime_error_to_sandbox_error(exc),
            )

        return SandboxResult(output=output, stdout=stdout, stderr=stderr)

    def execute(self, code: str) -> str:
        """Execute *code* and return output as a plain string.

        This matches the ``(code: str) -> str`` executor interface expected
        by ida-chat-plugin's ``script_executor`` parameter, making it a
        drop-in replacement for the default ``exec()``-based executor::

            sandbox = IdaSandbox(db)
            core = IDAChatCore(db=db, callback=cb, script_executor=sandbox.execute)

        On success the captured stdout is returned.  On error a
        human-readable error description is returned so the LLM can
        self-correct.
        """
        result = self.run(code)
        if result.ok:
            return "".join(result.stdout)
        assert result.error is not None  # guaranteed by not result.ok
        return f"Script error ({result.error.kind}): {result.error.formatted}"

    @staticmethod
    def system_prompt() -> str:
        """Return the full system-prompt fragment for LLM integrations.

        Includes the language subset description, data model, example
        patterns, complete function reference, tips, and resource limits.
        Suitable for appending to an LLM system prompt so the model knows
        how to write sandbox-compatible analysis scripts.

        Example::

            options = ClaudeAgentOptions(
                system_prompt={
                    "type": "preset",
                    "preset": "claude_code",
                    "append": IdaSandbox.system_prompt(),
                },
            )
        """
        return (_PROMPTS_DIR / "system_prompt.md").read_text()

    @staticmethod
    def api_reference() -> str:
        """Return the function-reference tables only.

        A smaller prompt fragment listing every sandbox function, its
        return type, and a short description.  Use this when you want to
        build a custom system prompt and only need the API docs.

        Example::

            custom_prompt = "You are a binary analyst.\\n" + IdaSandbox.api_reference()
        """
        return (_PROMPTS_DIR / "api_reference.md").read_text()
