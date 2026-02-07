"""IDA Sandbox: a Monty-based sandbox exposing IDA Pro analysis routines.

Creates a secure execution environment where sandboxed Python code can call
a limited set of IDA Pro analysis functions backed by ida_domain.
"""

import random as _random

import pydantic_monty


# The set of function names exposed into every sandbox.
SANDBOX_FUNCTION_NAMES = [
    "enumerate_functions",
    "disassemble_function",
    "get_xrefs_to",
    "get_xrefs_from",
    "read_bytes",
    "random_int",
]


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


class IdaSandbox:
    """A Monty sandbox with IDA Pro analysis routines exposed.

    Usage::

        from ida_domain import Database
        from ida_sandbox import IdaSandbox

        with Database.open(path, options) as db:
            sandbox = IdaSandbox(db)
            output = []
            sandbox.run(code, print_callback=lambda s, t: output.append(t))
    """

    def __init__(self, db):
        self.db = db
        self._fn_impls = _build_ida_functions(db)

    def run(self, code, print_callback=None):
        """Evaluate *code* in the sandbox.

        Args:
            code: Python source code to evaluate inside the sandbox.
            print_callback: Optional ``(stream, text)`` callback for captured
                ``print()`` output from the sandboxed code.

        Returns:
            The value of the last expression in *code*.
        """
        m = pydantic_monty.Monty(
            code,
            external_functions=SANDBOX_FUNCTION_NAMES,
        )
        return m.run(
            external_functions=self._fn_impls,
            print_callback=print_callback,
        )
