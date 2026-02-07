"""Tests for the IDA Sandbox.

Three layers tested against a real IDA Pro database
(tests/data/Practical Malware Analysis Lab 01-01.exe_):

  Layer 1 — Monty sandbox basics (no IDA):
    Verify the Monty interpreter runs code, calls external functions,
    and handles print callbacks.

  Layer 2 — IDA wrapper functions (direct calls):
    Verify each wrapper function in build_ida_functions() returns
    correctly shaped data from real IDA analysis.

  Layer 3 — Sandbox integration:
    Verify scripts executed through IdaSandbox.run() can call IDA
    functions, and that resource limits, type checking, and structured
    error handling work correctly.
"""

import pydantic_monty

from ida_codemode_api import (
    FUNCTION_NAMES,
    TYPE_STUBS,
)
from ida_sandbox.sandbox import (
    IdaSandbox,
    SandboxError,
    SandboxResult,
)


# ===========================================================================
# Layer 1 — Monty basics (no IDA)
# ===========================================================================


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


# ===========================================================================
# Layer 2 — IDA wrapper functions (direct calls against real DB)
# ===========================================================================


class TestBinaryInfo:
    """get_binary_info() — database metadata."""

    def test_returns_expected_keys(self, ida_fns):
        info = ida_fns["get_binary_info"]()
        expected_keys = {
            "path", "module", "architecture", "bitness", "format",
            "base_address", "entry_point", "minimum_ea", "maximum_ea",
            "filesize", "md5", "sha256", "crc32",
        }
        assert expected_keys == set(info.keys())

    def test_architecture_is_metapc(self, ida_fns):
        info = ida_fns["get_binary_info"]()
        assert info["architecture"] == "metapc"

    def test_bitness_is_32(self, ida_fns):
        info = ida_fns["get_binary_info"]()
        assert info["bitness"] == 32

    def test_format_is_pe(self, ida_fns):
        info = ida_fns["get_binary_info"]()
        assert "PE" in info["format"]

    def test_hashes_are_hex_strings(self, ida_fns):
        info = ida_fns["get_binary_info"]()
        assert len(info["md5"]) == 32
        int(info["md5"], 16)  # valid hex
        assert len(info["sha256"]) == 64
        int(info["sha256"], 16)

    def test_via_sandbox(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run('get_binary_info()["architecture"]')
        assert result.ok
        assert result.output == "metapc"


class TestFunctionEnumeration:
    """enumerate_functions(), get_function_by_name()."""

    def test_enumerate_returns_functions(self, ida_fns):
        functions = ida_fns["enumerate_functions"]()
        assert len(functions) >= 1

    def test_function_dict_shape(self, ida_fns):
        functions = ida_fns["enumerate_functions"]()
        for f in functions:
            assert {"address", "name", "size"} == set(f.keys())
            assert isinstance(f["address"], int)
            assert isinstance(f["name"], str)
            assert isinstance(f["size"], int)
            assert f["size"] > 0

    def test_get_function_by_name_found(self, ida_fns):
        functions = ida_fns["enumerate_functions"]()
        # Look up the first function by name — it must be found
        first = functions[0]
        result = ida_fns["get_function_by_name"](first["name"])
        assert result is not None
        assert result["address"] == first["address"]

    def test_get_function_by_name_not_found(self, ida_fns):
        assert ida_fns["get_function_by_name"]("_nonexistent_xyz_") is None

    def test_enumerate_via_sandbox(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run("len(enumerate_functions())")
        assert result.ok
        assert result.output >= 1


class TestFunctionAnalysis:
    """disassemble, decompile, signature, callers, callees, basic_blocks."""

    def test_disassemble(self, ida_fns, first_func):
        lines = ida_fns["disassemble_function"](first_func["address"])
        assert len(lines) > 0
        assert all(isinstance(line, str) for line in lines)

    def test_disassemble_unknown_address(self, ida_fns):
        assert ida_fns["disassemble_function"](0xDEADDEAD) == []

    def test_decompile_returns_list(self, ida_fns, first_func):
        # May be empty if Hex-Rays is unavailable — that's fine
        lines = ida_fns["decompile_function"](first_func["address"])
        assert isinstance(lines, list)

    def test_decompile_unknown_address(self, ida_fns):
        assert ida_fns["decompile_function"](0xDEADDEAD) == []

    def test_get_function_signature(self, ida_fns, first_func):
        sig = ida_fns["get_function_signature"](first_func["address"])
        assert sig is None or isinstance(sig, str)

    def test_get_function_signature_unknown(self, ida_fns):
        assert ida_fns["get_function_signature"](0xDEADDEAD) is None

    def test_get_callers(self, ida_fns, first_func):
        callers = ida_fns["get_callers"](first_func["address"])
        assert isinstance(callers, list)
        for c in callers:
            assert {"address", "name"} == set(c.keys())

    def test_get_callers_unknown(self, ida_fns):
        assert ida_fns["get_callers"](0xDEADDEAD) == []

    def test_get_callees(self, ida_fns, first_func):
        callees = ida_fns["get_callees"](first_func["address"])
        assert isinstance(callees, list)
        for c in callees:
            assert {"address", "name"} == set(c.keys())

    def test_get_callees_unknown(self, ida_fns):
        assert ida_fns["get_callees"](0xDEADDEAD) == []

    def test_get_basic_blocks(self, ida_fns, first_func):
        blocks = ida_fns["get_basic_blocks"](first_func["address"])
        assert len(blocks) >= 1
        for b in blocks:
            assert {"start", "end", "successors", "predecessors"} == set(b.keys())
            assert isinstance(b["start"], int)
            assert isinstance(b["end"], int)
            assert b["end"] > b["start"]

    def test_get_basic_blocks_unknown(self, ida_fns):
        assert ida_fns["get_basic_blocks"](0xDEADDEAD) == []

    def test_disassemble_via_sandbox(self, db):
        sandbox = IdaSandbox(db)
        code = """\
fns = enumerate_functions()
lines = disassemble_function(fns[0]["address"])
len(lines)
"""
        result = sandbox.run(code)
        assert result.ok
        assert result.output > 0


class TestXrefs:
    """get_xrefs_to(), get_xrefs_from()."""

    def test_xrefs_to_shape(self, ida_fns, first_func):
        xrefs = ida_fns["get_xrefs_to"](first_func["address"])
        assert isinstance(xrefs, list)
        for x in xrefs:
            assert {"from_address", "type", "is_call", "is_jump"} == set(x.keys())
            assert isinstance(x["from_address"], int)
            assert isinstance(x["type"], str)
            assert isinstance(x["is_call"], bool)
            assert isinstance(x["is_jump"], bool)

    def test_xrefs_to_unmapped(self, ida_fns):
        assert ida_fns["get_xrefs_to"](0xDEADDEAD) == []

    def test_xrefs_from_shape(self, ida_fns, first_func):
        xrefs = ida_fns["get_xrefs_from"](first_func["address"])
        assert isinstance(xrefs, list)
        for x in xrefs:
            assert {"to_address", "type", "is_call", "is_jump"} == set(x.keys())

    def test_xrefs_from_unmapped(self, ida_fns):
        assert ida_fns["get_xrefs_from"](0xDEADDEAD) == []

    def test_xrefs_via_sandbox(self, db):
        sandbox = IdaSandbox(db)
        code = """\
fns = enumerate_functions()
xrefs = get_xrefs_from(fns[0]["address"])
len(xrefs)
"""
        result = sandbox.run(code)
        assert result.ok
        assert isinstance(result.output, int)


class TestStrings:
    """enumerate_strings(), get_string_at()."""

    def test_enumerate_returns_strings(self, ida_fns):
        strings = ida_fns["enumerate_strings"]()
        assert len(strings) >= 1

    def test_string_dict_shape(self, ida_fns):
        strings = ida_fns["enumerate_strings"]()
        for s in strings:
            assert {"address", "length", "type", "value"} == set(s.keys())
            assert isinstance(s["address"], int)
            assert isinstance(s["length"], int)
            assert isinstance(s["type"], str)
            assert isinstance(s["value"], str)

    def test_get_string_at_known_address(self, ida_fns):
        strings = ida_fns["enumerate_strings"]()
        if strings:
            result = ida_fns["get_string_at"](strings[0]["address"])
            assert result is not None
            assert isinstance(result, str)

    def test_strings_via_sandbox(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run("len(enumerate_strings())")
        assert result.ok
        assert result.output >= 1


class TestSegments:
    """enumerate_segments()."""

    def test_returns_segments(self, ida_fns):
        segs = ida_fns["enumerate_segments"]()
        assert len(segs) >= 1

    def test_segment_dict_shape(self, ida_fns):
        segs = ida_fns["enumerate_segments"]()
        for s in segs:
            assert {"name", "start", "end", "size", "permissions", "class", "bitness"} == set(s.keys())
            assert isinstance(s["start"], int)
            assert isinstance(s["end"], int)
            assert s["end"] > s["start"]
            assert s["size"] == s["end"] - s["start"]

    def test_has_code_segment(self, ida_fns):
        segs = ida_fns["enumerate_segments"]()
        classes = {s["class"] for s in segs}
        assert "CODE" in classes

    def test_segments_via_sandbox(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run("len(enumerate_segments())")
        assert result.ok
        assert result.output >= 1


class TestNames:
    """enumerate_names(), get_name_at(), demangle_name()."""

    def test_enumerate_returns_names(self, ida_fns):
        names = ida_fns["enumerate_names"]()
        assert len(names) >= 1

    def test_name_dict_shape(self, ida_fns):
        names = ida_fns["enumerate_names"]()
        for n in names:
            assert {"address", "name"} == set(n.keys())
            assert isinstance(n["address"], int)
            assert isinstance(n["name"], str)

    def test_get_name_at_known(self, ida_fns):
        names = ida_fns["enumerate_names"]()
        if names:
            result = ida_fns["get_name_at"](names[0]["address"])
            assert result is not None
            assert isinstance(result, str)

    def test_get_name_at_unmapped(self, ida_fns):
        assert ida_fns["get_name_at"](0xDEADDEAD) is None

    def test_demangle_plain_name(self, ida_fns):
        # Unmangled name should pass through unchanged
        result = ida_fns["demangle_name"]("main")
        assert result == "main"

    def test_names_via_sandbox(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run("len(enumerate_names())")
        assert result.ok
        assert result.output >= 1


class TestImportsAndEntries:
    """enumerate_imports(), enumerate_entries()."""

    def test_imports_non_empty(self, ida_fns):
        imports = ida_fns["enumerate_imports"]()
        assert len(imports) >= 1

    def test_import_dict_shape(self, ida_fns):
        imports = ida_fns["enumerate_imports"]()
        for imp in imports:
            assert {"address", "name", "module", "ordinal"} == set(imp.keys())
            assert isinstance(imp["address"], int)
            assert isinstance(imp["name"], str)
            assert isinstance(imp["module"], str)
            assert isinstance(imp["ordinal"], int)

    def test_entries_non_empty(self, ida_fns):
        entries = ida_fns["enumerate_entries"]()
        assert len(entries) >= 1

    def test_entry_dict_shape(self, ida_fns):
        entries = ida_fns["enumerate_entries"]()
        for e in entries:
            assert "ordinal" in e
            assert "address" in e
            assert "name" in e
            assert "forwarder" in e

    def test_imports_via_sandbox(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run("len(enumerate_imports())")
        assert result.ok
        assert result.output >= 1


class TestBytesAndMemory:
    """read_bytes(), find_bytes(), get_disassembly_at(), get_instruction_at()."""

    def test_read_bytes(self, ida_fns, first_func):
        data = ida_fns["read_bytes"](first_func["address"], 4)
        assert len(data) == 4
        assert all(0 <= b <= 255 for b in data)

    def test_read_bytes_unmapped(self, ida_fns):
        assert ida_fns["read_bytes"](0xDEADDEAD, 4) == []

    def test_find_bytes_round_trip(self, ida_fns, first_func):
        # Read the first function's prologue and search for it
        prologue = ida_fns["read_bytes"](first_func["address"], 4)
        found = ida_fns["find_bytes"](prologue)
        assert first_func["address"] in found

    def test_find_bytes_not_found(self, ida_fns):
        assert ida_fns["find_bytes"]([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]) == []

    def test_get_disassembly_at(self, ida_fns, first_func):
        result = ida_fns["get_disassembly_at"](first_func["address"])
        assert result is not None
        assert isinstance(result, str)
        assert len(result) > 0

    def test_get_disassembly_at_unmapped(self, ida_fns):
        assert ida_fns["get_disassembly_at"](0xDEADDEAD) is None

    def test_get_instruction_at(self, ida_fns, first_func):
        insn = ida_fns["get_instruction_at"](first_func["address"])
        assert insn is not None
        assert {"address", "size", "mnemonic", "disassembly", "is_call"} == set(insn.keys())
        assert insn["address"] == first_func["address"]
        assert insn["size"] > 0
        assert isinstance(insn["mnemonic"], str)
        assert isinstance(insn["is_call"], bool)

    def test_get_instruction_at_unmapped(self, ida_fns):
        assert ida_fns["get_instruction_at"](0xDEADDEAD) is None

    def test_read_bytes_via_sandbox(self, db):
        sandbox = IdaSandbox(db)
        code = """\
fns = enumerate_functions()
raw = read_bytes(fns[0]["address"], 4)
len(raw)
"""
        result = sandbox.run(code)
        assert result.ok
        assert result.output == 4


class TestAddressClassification:
    """is_code_at(), is_data_at(), is_valid_address()."""

    def test_function_address_is_code(self, ida_fns, first_func):
        assert ida_fns["is_code_at"](first_func["address"]) is True

    def test_function_address_is_valid(self, ida_fns, first_func):
        assert ida_fns["is_valid_address"](first_func["address"]) is True

    def test_invalid_address(self, ida_fns):
        assert ida_fns["is_valid_address"](0xDEADDEAD) is False

    def test_is_data_returns_bool(self, ida_fns, first_func):
        # Doesn't matter which value — just verify it returns a bool
        result = ida_fns["is_data_at"](first_func["address"])
        assert isinstance(result, bool)

    def test_via_sandbox(self, db):
        sandbox = IdaSandbox(db)
        code = """\
fns = enumerate_functions()
is_code_at(fns[0]["address"])
"""
        result = sandbox.run(code)
        assert result.ok
        assert result.output is True

    def test_invalid_via_sandbox(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run("is_valid_address(0xDEADDEAD)")
        assert result.ok
        assert result.output is False


class TestComments:
    """get_comment_at()."""

    def test_no_comment_on_fresh_db(self, ida_fns, first_func):
        # A freshly analyzed binary has no user comments
        comment = ida_fns["get_comment_at"](first_func["address"])
        assert comment is None

    def test_via_sandbox(self, db):
        sandbox = IdaSandbox(db)
        code = """\
fns = enumerate_functions()
get_comment_at(fns[0]["address"])
"""
        result = sandbox.run(code)
        assert result.ok
        assert result.output is None


class TestRandomInt:
    """random_int()."""

    def test_in_range(self, ida_fns):
        for _ in range(10):
            val = ida_fns["random_int"](0, 100)
            assert 0 <= val <= 100

    def test_via_sandbox(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run("random_int(10, 20)")
        assert result.ok
        assert 10 <= result.output <= 20


# ===========================================================================
# Layer 3 — Sandbox integration
# ===========================================================================


class TestSandboxIntegration:
    """IdaSandbox creation, run(), and output capture."""

    def test_create(self, db):
        sandbox = IdaSandbox(db)
        assert sandbox.db is db
        assert set(FUNCTION_NAMES).issubset(sandbox._fn_impls.keys())

    def test_run_returns_sandbox_result(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run("1 + 1")
        assert isinstance(result, SandboxResult)
        assert result.ok is True
        assert result.output == 2
        assert result.error is None

    def test_stdout_capture(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run('print("sandbox says hi")')
        assert result.ok
        assert "sandbox says hi" in "".join(result.stdout)

    def test_print_callback(self, db):
        sandbox = IdaSandbox(db)
        cb_output = []
        result = sandbox.run(
            'print("hello")',
            print_callback=lambda _s, t: cb_output.append(t),
        )
        assert result.ok
        assert "hello" in "".join(cb_output)
        assert "hello" in "".join(result.stdout)


class TestResourceLimits:
    """Resource limit enforcement."""

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
        assert "time limit" in result.error.message

    def test_memory(self, db):
        sandbox = IdaSandbox(
            db,
            limits=pydantic_monty.ResourceLimits(max_memory=1000),
        )
        result = sandbox.run("x = [0] * 10000000")
        assert not result.ok
        assert result.error.kind == "runtime"
        assert result.error.inner_type == "MemoryError"

    def test_recursion(self, db):
        sandbox = IdaSandbox(
            db,
            limits=pydantic_monty.ResourceLimits(max_recursion_depth=5),
        )
        result = sandbox.run("def f():\n    f()\nf()")
        assert not result.ok
        assert result.error.kind == "runtime"
        assert result.error.inner_type == "RecursionError"

    def test_normal_code_passes(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run("sum(range(1000))")
        assert result.ok
        assert result.output == 499500


class TestTypeChecking:
    """Opt-in static type checking."""

    def test_off_by_default(self, db):
        assert IdaSandbox(db).type_check is False

    def test_valid_code_passes(self, db):
        sandbox = IdaSandbox(db, type_check=True)
        result = sandbox.run("1 + 2")
        assert result.ok
        assert result.output == 3

    def test_catches_type_error(self, db):
        sandbox = IdaSandbox(db, type_check=True)
        result = sandbox.run('1 + "a"')
        assert not result.ok
        assert result.error.kind == "typing"

    def test_catches_wrong_arg_type(self, db):
        sandbox = IdaSandbox(db, type_check=True)
        result = sandbox.run('disassemble_function("not_an_int")')
        assert not result.ok
        assert result.error.kind == "typing"

    def test_stubs_cover_all_functions(self):
        for name in FUNCTION_NAMES:
            assert f"def {name}(" in TYPE_STUBS, f"stub missing for {name}"

    def test_valid_sandbox_calls_pass(self, db):
        sandbox = IdaSandbox(db, type_check=True)
        result = sandbox.run("len(enumerate_functions())")
        assert result.ok

    def test_enumeration_functions_pass(self, db):
        """All no-arg enumeration functions pass type checking."""
        sandbox = IdaSandbox(db, type_check=True)
        code = """\
info = get_binary_info()
segs = enumerate_segments()
names = enumerate_names()
imports = enumerate_imports()
entries = enumerate_entries()
strings = enumerate_strings()
len(info) + len(segs) + len(names) + len(imports) + len(entries) + len(strings)
"""
        result = sandbox.run(code)
        assert result.ok


class TestErrorHandling:
    """Structured error handling via SandboxResult / SandboxError."""

    def test_division_by_zero(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run("1 / 0")
        assert not result.ok
        assert result.error.kind == "runtime"
        assert result.error.inner_type == "ZeroDivisionError"
        assert "division by zero" in result.error.message
        assert "Traceback" in result.error.formatted

    def test_name_error(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run("undefined_variable")
        assert not result.ok
        assert result.error.kind == "runtime"
        assert result.error.inner_type == "NameError"

    def test_syntax_error(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run("if")
        assert not result.ok
        assert result.error.kind == "syntax"

    def test_preserves_partial_stdout(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run('print("before")\n1 / 0')
        assert not result.ok
        assert "before" in "".join(result.stdout)
        assert result.error.kind == "runtime"

    def test_ok_property(self, db):
        sandbox = IdaSandbox(db)
        assert sandbox.run("42").ok is True
        assert sandbox.run("1/0").ok is False

    def test_error_fields(self, db):
        sandbox = IdaSandbox(db)
        err = sandbox.run("1/0").error
        assert isinstance(err, SandboxError)
        assert isinstance(err.kind, str)
        assert isinstance(err.message, str)
        assert isinstance(err.formatted, str)


# ===========================================================================
# End-to-end — comprehensive analysis script against real IDA data
# ===========================================================================


class TestEndToEnd:
    """Full analysis scripts exercising many functions together."""

    ANALYSIS_SCRIPT = """\
# --- Binary metadata ---
info = get_binary_info()
print("arch: " + info["architecture"])
print("bitness: " + str(info["bitness"]))
print("md5: " + info["md5"])

# --- Functions ---
functions = enumerate_functions()
print("functions: " + str(len(functions)))
first = functions[0]
print("first: " + first["name"] + " at " + hex(first["address"]))

# --- Disassemble first function ---
disasm = disassemble_function(first["address"])
print("disasm lines: " + str(len(disasm)))

# --- Basic blocks ---
blocks = get_basic_blocks(first["address"])
print("blocks: " + str(len(blocks)))

# --- Callers / callees ---
callers = get_callers(first["address"])
print("callers: " + str(len(callers)))
callees = get_callees(first["address"])
print("callees: " + str(len(callees)))

# --- Cross-references ---
xrefs_from = get_xrefs_from(first["address"])
print("xrefs from: " + str(len(xrefs_from)))

# --- Strings ---
strings = enumerate_strings()
print("strings: " + str(len(strings)))

# --- Segments ---
segments = enumerate_segments()
print("segments: " + str(len(segments)))

# --- Names ---
names = enumerate_names()
print("names: " + str(len(names)))

# --- Imports & entries ---
imports = enumerate_imports()
print("imports: " + str(len(imports)))
entries = enumerate_entries()
print("entries: " + str(len(entries)))

# --- Bytes ---
raw = read_bytes(first["address"], 4)
print("first bytes: " + str(len(raw)))
found = find_bytes(raw)
print("prologue hits: " + str(len(found)))

# --- Instruction ---
insn = get_instruction_at(first["address"])
print("mnemonic: " + insn["mnemonic"])

# --- Disassembly at ---
disasm_line = get_disassembly_at(first["address"])
print("disasm at: " + str(disasm_line))

# --- Classification ---
print("is code: " + str(is_code_at(first["address"])))
print("is valid: " + str(is_valid_address(first["address"])))
print("invalid: " + str(is_valid_address(0xDEADDEAD)))

# --- Comment ---
comment = get_comment_at(first["address"])
print("comment: " + str(comment))

# --- Demangle ---
dm = demangle_name("main")
print("demangled: " + dm)

# --- Random ---
r = random_int(1, 100)
print("random: " + str(r))
"""

    def test_comprehensive_analysis(self, db):
        sandbox = IdaSandbox(db)
        result = sandbox.run(self.ANALYSIS_SCRIPT)
        assert result.ok, f"Script failed: {result.error}"
        text = "".join(result.stdout)

        assert "arch: metapc" in text
        assert "bitness: 32" in text
        assert "md5:" in text
        assert "functions:" in text
        assert "disasm lines:" in text
        assert "blocks:" in text
        assert "strings:" in text
        assert "segments:" in text
        assert "names:" in text
        assert "imports:" in text
        assert "entries:" in text
        assert "first bytes: 4" in text
        assert "prologue hits:" in text
        assert "mnemonic:" in text
        assert "is code: True" in text
        assert "is valid: True" in text
        assert "invalid: False" in text
        assert "comment: None" in text
        assert "demangled: main" in text
        assert "random:" in text

    def test_comprehensive_with_type_check(self, db):
        """Type-checked variant avoids subscripting Optional returns."""
        sandbox = IdaSandbox(db, type_check=True)
        code = """\
info = get_binary_info()
print("arch: " + info["architecture"])
functions = enumerate_functions()
print("count: " + str(len(functions)))
strings = enumerate_strings()
segments = enumerate_segments()
names = enumerate_names()
imports = enumerate_imports()
entries = enumerate_entries()
disasm = disassemble_function(functions[0]["address"])
print("disasm: " + str(len(disasm)))
raw = read_bytes(functions[0]["address"], 4)
print("bytes: " + str(len(raw)))
print("code: " + str(is_code_at(functions[0]["address"])))
dm = demangle_name("main")
print("dm: " + dm)
r = random_int(1, 100)
print("r: " + str(r))
"""
        result = sandbox.run(code)
        assert result.ok, f"Type-check script failed: {result.error}"
        text = "".join(result.stdout)
        assert "arch: metapc" in text


# ===========================================================================
# Layer 4 – Integration helpers (execute, system_prompt, api_reference)
# ===========================================================================


class TestExecuteAdapter:
    """Tests for IdaSandbox.execute() — the (str) -> str adapter."""

    def test_success_returns_stdout(self, db):
        sandbox = IdaSandbox(db)
        output = sandbox.execute('print("hello")')
        assert "hello" in output

    def test_multi_line_stdout(self, db):
        sandbox = IdaSandbox(db)
        output = sandbox.execute('print("a")\nprint("b")')
        assert "a" in output
        assert "b" in output

    def test_error_returns_description(self, db):
        sandbox = IdaSandbox(db)
        output = sandbox.execute("1 / 0")
        assert "Script error" in output
        assert "runtime" in output

    def test_syntax_error_returns_description(self, db):
        sandbox = IdaSandbox(db)
        output = sandbox.execute("def")
        assert "Script error" in output
        assert "syntax" in output

    def test_empty_stdout_on_success(self, db):
        sandbox = IdaSandbox(db)
        output = sandbox.execute("x = 1 + 1")
        assert isinstance(output, str)

    def test_ida_functions_accessible(self, db):
        sandbox = IdaSandbox(db)
        output = sandbox.execute(
            'info = get_binary_info()\nprint(info["architecture"])'
        )
        assert "metapc" in output

    def test_matches_executor_interface(self, db):
        """execute() is callable as (str) -> str, matching ida-chat-plugin."""
        sandbox = IdaSandbox(db)
        fn = sandbox.execute
        assert callable(fn)
        result = fn('print("ok")')
        assert isinstance(result, str)


class TestSystemPrompt:
    """Tests for IdaSandbox.system_prompt()."""

    def test_returns_string(self):
        prompt = IdaSandbox.system_prompt()
        assert isinstance(prompt, str)
        assert len(prompt) > 100

    def test_contains_function_reference(self):
        prompt = IdaSandbox.system_prompt()
        assert "enumerate_functions" in prompt
        assert "get_binary_info" in prompt
        assert "get_xrefs_to" in prompt

    def test_contains_language_subset(self):
        prompt = IdaSandbox.system_prompt()
        assert "Language subset" in prompt

    def test_contains_examples(self):
        prompt = IdaSandbox.system_prompt()
        assert "Patterns and examples" in prompt

    def test_contains_tips(self):
        prompt = IdaSandbox.system_prompt()
        assert "Tips" in prompt

    def test_contains_data_model(self):
        prompt = IdaSandbox.system_prompt()
        assert "Data model" in prompt

    def test_callable_as_static_method(self):
        """Can be called without an instance."""
        prompt = IdaSandbox.system_prompt()
        assert isinstance(prompt, str)


class TestApiReference:
    """Tests for IdaSandbox.api_reference()."""

    def test_returns_string(self):
        ref = IdaSandbox.api_reference()
        assert isinstance(ref, str)
        assert len(ref) > 100

    def test_contains_all_function_categories(self):
        ref = IdaSandbox.api_reference()
        assert "Database metadata" in ref
        assert "Functions" in ref
        assert "Cross-references" in ref
        assert "Strings" in ref
        assert "Segments" in ref
        assert "Names / symbols" in ref
        assert "Imports and entries" in ref
        assert "Bytes / memory" in ref
        assert "Address classification" in ref
        assert "Comments" in ref
        assert "Utilities" in ref

    def test_contains_all_28_functions(self):
        ref = IdaSandbox.api_reference()
        expected = [
            "get_binary_info",
            "enumerate_functions",
            "get_function_by_name",
            "disassemble_function",
            "decompile_function",
            "get_function_signature",
            "get_callers",
            "get_callees",
            "get_basic_blocks",
            "get_xrefs_to",
            "get_xrefs_from",
            "enumerate_strings",
            "get_string_at",
            "enumerate_segments",
            "enumerate_names",
            "get_name_at",
            "demangle_name",
            "enumerate_imports",
            "enumerate_entries",
            "read_bytes",
            "find_bytes",
            "get_disassembly_at",
            "get_instruction_at",
            "is_code_at",
            "is_data_at",
            "is_valid_address",
            "get_comment_at",
            "random_int",
        ]
        for fn_name in expected:
            assert fn_name in ref, f"Missing function: {fn_name}"

    def test_is_subset_of_system_prompt(self):
        """api_reference content should appear within system_prompt."""
        ref = IdaSandbox.api_reference()
        prompt = IdaSandbox.system_prompt()
        # The function reference tables should be in the system prompt
        assert "enumerate_functions" in ref
        assert "enumerate_functions" in prompt

    def test_callable_as_static_method(self):
        """Can be called without an instance."""
        ref = IdaSandbox.api_reference()
        assert isinstance(ref, str)
