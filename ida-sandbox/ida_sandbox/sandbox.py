"""IDA Sandbox: a Monty-based sandbox exposing IDA Pro analysis routines.

Creates a secure execution environment where sandboxed Python code can call
a limited set of IDA Pro analysis functions backed by ida_domain.
"""

from __future__ import annotations

import random as _random
from dataclasses import dataclass, field

import pydantic_monty


# ---------------------------------------------------------------------------
# Structured result and error types
# ---------------------------------------------------------------------------


@dataclass
class SandboxError:
    """Structured representation of an error raised during sandbox execution."""

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
    """Structured return value from :meth:`IdaSandbox.run`."""

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
# Type-checking stubs for every sandbox function
# ---------------------------------------------------------------------------

TYPE_STUBS = """\
from typing import Any

def enumerate_functions() -> list[dict[str, Any]]:
    \"\"\"Return [{address: int, name: str, size: int}, ...].\"\"\"
    ...

def disassemble_function(address: int) -> list[str]:
    \"\"\"Return disassembly lines for the function at *address*.\"\"\"
    ...

def get_xrefs_to(address: int) -> list[dict[str, Any]]:
    \"\"\"Return xrefs TO *address*: [{from_address, type, is_call, is_jump}, ...].\"\"\"
    ...

def get_xrefs_from(address: int) -> list[dict[str, Any]]:
    \"\"\"Return xrefs FROM *address*: [{to_address, type, is_call, is_jump}, ...].\"\"\"
    ...

def read_bytes(address: int, size: int) -> list[int]:
    \"\"\"Return *size* bytes at *address* as a list of ints.\"\"\"
    ...

def random_int(low: int, high: int) -> int:
    \"\"\"Return a random integer in [low, high].\"\"\"
    ...
"""


# ---------------------------------------------------------------------------
# Sandbox function names
# ---------------------------------------------------------------------------

# The set of function names exposed into every sandbox.
SANDBOX_FUNCTION_NAMES = [
    "enumerate_functions",
    "disassemble_function",
    "get_xrefs_to",
    "get_xrefs_from",
    "read_bytes",
    "random_int",
]


# ---------------------------------------------------------------------------
# IDA-backed function builder
# ---------------------------------------------------------------------------


def _build_ida_functions(db):
    """Build the IDA-backed function implementations that will be callable
    from inside the Monty sandbox.

    Each function serializes IDA domain objects into plain Python types
    (dicts, lists, ints, strings) so they can cross the sandbox boundary.
    """

    def enumerate_functions():
        """Return a list of all functions: [{address, name, size}, ...]."""
        results = []
        for func in db.functions:
            results.append({
                "address": func.start_ea,
                "name": db.functions.get_name(func),
                "size": func.size() if callable(func.size) else func.size,
            })
        return results

    def disassemble_function(address):
        """Return disassembly lines for the function at *address*."""
        func = db.functions.get_at(address)
        if func is None:
            return []
        return list(db.functions.get_disassembly(func))

    def get_xrefs_to(address):
        """Return cross-references TO *address*: [{from_address, type, is_call, is_jump}, ...]."""
        results = []
        for xref in db.xrefs.to_ea(address):
            results.append({
                "from_address": xref.from_ea,
                "type": xref.type.name,
                "is_call": xref.is_call,
                "is_jump": xref.is_jump,
            })
        return results

    def get_xrefs_from(address):
        """Return cross-references FROM *address*: [{to_address, type, is_call, is_jump}, ...]."""
        results = []
        for xref in db.xrefs.from_ea(address):
            results.append({
                "to_address": xref.to_ea,
                "type": xref.type.name,
                "is_call": xref.is_call,
                "is_jump": xref.is_jump,
            })
        return results

    def read_bytes(address, size):
        """Return *size* bytes starting at *address* as a list of ints."""
        data = db.bytes.get_bytes_at(address, size)
        if data is None:
            return []
        return list(data)

    def random_int(low, high):
        """Return a random integer in [low, high]."""
        return _random.randint(low, high)

    return {
        "enumerate_functions": enumerate_functions,
        "disassemble_function": disassemble_function,
        "get_xrefs_to": get_xrefs_to,
        "get_xrefs_from": get_xrefs_from,
        "read_bytes": read_bytes,
        "random_int": random_int,
    }


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
        from ida_sandbox import IdaSandbox

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
        db,
        *,
        limits: pydantic_monty.ResourceLimits | None = None,
        type_check: bool = False,
    ):
        self.db = db
        self.limits = limits if limits is not None else dict(DEFAULT_LIMITS)
        self.type_check = type_check
        self._fn_impls = _build_ida_functions(db)

    def run(self, code: str, print_callback=None) -> SandboxResult:
        """Evaluate *code* in the sandbox.

        Args:
            code: Python source code to evaluate inside the sandbox.
            print_callback: Optional ``(stream, text)`` callback for captured
                ``print()`` output.  If supplied, it is called *in addition
                to* the result's ``stdout``/``stderr`` lists.

        Returns:
            A :class:`SandboxResult` with the script output, captured prints,
            and any error that occurred.
        """
        stdout: list[str] = []
        stderr: list[str] = []

        def _capture(stream: str, text: str):
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
                external_functions=SANDBOX_FUNCTION_NAMES,
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
