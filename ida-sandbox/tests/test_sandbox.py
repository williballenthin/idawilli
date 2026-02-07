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
# IDA function wrappers (via mock db) — original 6
# ---------------------------------------------------------------------------


class TestIdaFunctions:
    """Test each original IDA-backed function built by _build_ida_functions."""

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
# New IDA function wrappers — database metadata
# ---------------------------------------------------------------------------


class TestGetBinaryInfo:
    """Test get_binary_info()."""

    def test_returns_all_metadata_fields(self, mock_db):
        fns = _build_ida_functions(mock_db)
        info = fns["get_binary_info"]()
        assert info["path"] == "/mock/binary"
        assert info["module"] == "binary"
        assert info["architecture"] == "metapc"
        assert info["bitness"] == 64
        assert info["format"] == "ELF64"
        assert info["base_address"] == 0
        assert info["entry_point"] == 0x401060
        assert info["minimum_ea"] == 0x400000
        assert info["maximum_ea"] == 0x410000
        assert info["filesize"] == 65536
        assert info["md5"] == "d41d8cd98f00b204e9800998ecf8427e"
        assert info["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert info["crc32"] == 0

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run('info = get_binary_info()\ninfo["architecture"]')
        assert result.ok
        assert result.output == "metapc"

    def test_via_sandbox_bitness(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run('get_binary_info()["bitness"]')
        assert result.ok
        assert result.output == 64


# ---------------------------------------------------------------------------
# New IDA function wrappers — function lookup
# ---------------------------------------------------------------------------


class TestGetFunctionByName:
    """Test get_function_by_name()."""

    def test_found(self, mock_db):
        fns = _build_ida_functions(mock_db)
        result = fns["get_function_by_name"]("helper")
        assert result is not None
        assert result["address"] == 0x401100
        assert result["name"] == "helper"
        assert result["size"] == 16

    def test_not_found(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["get_function_by_name"]("nonexistent") is None

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run('f = get_function_by_name("main")\nf["address"]')
        assert result.ok
        assert result.output == 0x401000

    def test_via_sandbox_not_found(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run('get_function_by_name("nope")')
        assert result.ok
        assert result.output is None


# ---------------------------------------------------------------------------
# New IDA function wrappers — function analysis
# ---------------------------------------------------------------------------


class TestDecompileFunction:
    """Test decompile_function()."""

    def test_with_pseudocode(self, mock_db):
        fns = _build_ida_functions(mock_db)
        lines = fns["decompile_function"](0x401000)
        assert len(lines) == 5
        assert "int main(void) {" in lines
        assert "return 0;" in lines[3]

    def test_without_pseudocode(self, mock_db):
        fns = _build_ida_functions(mock_db)
        # helper has no pseudocode; should raise RuntimeError → return []
        lines = fns["decompile_function"](0x401100)
        assert lines == []

    def test_unknown_address(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["decompile_function"](0xDEAD) == []

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("len(decompile_function(0x401000))")
        assert result.ok
        assert result.output == 5


class TestGetFunctionSignature:
    """Test get_function_signature()."""

    def test_with_signature(self, mock_db):
        fns = _build_ida_functions(mock_db)
        sig = fns["get_function_signature"](0x401000)
        assert sig == "int __cdecl main(void)"

    def test_without_signature(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["get_function_signature"](0x401100) is None

    def test_unknown_address(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["get_function_signature"](0xDEAD) is None

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("get_function_signature(0x401000)")
        assert result.ok
        assert result.output == "int __cdecl main(void)"


class TestGetCallers:
    """Test get_callers()."""

    def test_with_callers(self, mock_db):
        fns = _build_ida_functions(mock_db)
        callers = fns["get_callers"](0x401100)
        assert len(callers) == 1
        assert callers[0]["address"] == 0x401000
        assert callers[0]["name"] == "main"

    def test_no_callers(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["get_callers"](0x401000) == []

    def test_unknown_address(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["get_callers"](0xDEAD) == []

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run(
            'callers = get_callers(0x401100)\ncallers[0]["name"]'
        )
        assert result.ok
        assert result.output == "main"


class TestGetCallees:
    """Test get_callees()."""

    def test_with_callees(self, mock_db):
        fns = _build_ida_functions(mock_db)
        callees = fns["get_callees"](0x401000)
        assert len(callees) == 2
        assert callees[0]["name"] == "helper"
        assert callees[1]["name"] == "cleanup"

    def test_no_callees(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["get_callees"](0x401200) == []

    def test_unknown_address(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["get_callees"](0xDEAD) == []

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("len(get_callees(0x401000))")
        assert result.ok
        assert result.output == 2


class TestGetBasicBlocks:
    """Test get_basic_blocks()."""

    def test_with_flowchart(self, mock_db):
        fns = _build_ida_functions(mock_db)
        blocks = fns["get_basic_blocks"](0x401000)
        assert len(blocks) == 2
        assert blocks[0]["start"] == 0x401000
        assert blocks[0]["end"] == 0x401010
        assert blocks[0]["successors"] == [0x401010]
        assert blocks[0]["predecessors"] == []
        assert blocks[1]["start"] == 0x401010
        assert blocks[1]["end"] == 0x401020
        assert blocks[1]["successors"] == []
        assert blocks[1]["predecessors"] == [0x401000]

    def test_no_flowchart(self, mock_db):
        fns = _build_ida_functions(mock_db)
        # helper has no flowchart
        assert fns["get_basic_blocks"](0x401100) == []

    def test_unknown_address(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["get_basic_blocks"](0xDEAD) == []

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run(
            'blocks = get_basic_blocks(0x401000)\nblocks[0]["start"]'
        )
        assert result.ok
        assert result.output == 0x401000


# ---------------------------------------------------------------------------
# New IDA function wrappers — strings
# ---------------------------------------------------------------------------


class TestEnumerateStrings:
    """Test enumerate_strings()."""

    def test_returns_all_strings(self, mock_db):
        fns = _build_ida_functions(mock_db)
        strings = fns["enumerate_strings"]()
        assert len(strings) == 2
        assert strings[0]["address"] == 0x402000
        assert strings[0]["length"] == 12
        assert strings[0]["type"] == "C"
        assert strings[0]["value"] == "Hello, %s!\n"
        assert strings[1]["value"] == "result = %d\n"

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("len(enumerate_strings())")
        assert result.ok
        assert result.output == 2

    def test_via_sandbox_access_value(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run('enumerate_strings()[0]["value"]')
        assert result.ok
        assert "Hello" in result.output


class TestGetStringAt:
    """Test get_string_at()."""

    def test_found(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["get_string_at"](0x402000) == "Hello, %s!\n"

    def test_not_found(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["get_string_at"](0x401000) is None

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("get_string_at(0x402000)")
        assert result.ok
        assert "Hello" in result.output


# ---------------------------------------------------------------------------
# New IDA function wrappers — segments
# ---------------------------------------------------------------------------


class TestEnumerateSegments:
    """Test enumerate_segments()."""

    def test_returns_all_segments(self, mock_db):
        fns = _build_ida_functions(mock_db)
        segs = fns["enumerate_segments"]()
        assert len(segs) == 2
        assert segs[0]["name"] == ".text"
        assert segs[0]["start"] == 0x401000
        assert segs[0]["end"] == 0x402000
        assert segs[0]["size"] == 0x1000
        assert segs[0]["permissions"] == 5
        assert segs[0]["class"] == "CODE"
        assert segs[0]["bitness"] == 64
        assert segs[1]["name"] == ".rodata"
        assert segs[1]["class"] == "DATA"

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("len(enumerate_segments())")
        assert result.ok
        assert result.output == 2

    def test_via_sandbox_access_field(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run('enumerate_segments()[0]["name"]')
        assert result.ok
        assert result.output == ".text"


# ---------------------------------------------------------------------------
# New IDA function wrappers — names / symbols
# ---------------------------------------------------------------------------


class TestEnumerateNames:
    """Test enumerate_names()."""

    def test_returns_all_names(self, mock_db):
        fns = _build_ida_functions(mock_db)
        names = fns["enumerate_names"]()
        assert len(names) == 4
        assert names[0] == {"address": 0x401000, "name": "main"}
        assert names[1] == {"address": 0x401100, "name": "helper"}
        assert names[3] == {"address": 0x402000, "name": "aHelloS"}

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("len(enumerate_names())")
        assert result.ok
        assert result.output == 4


class TestGetNameAt:
    """Test get_name_at()."""

    def test_found(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["get_name_at"](0x401000) == "main"

    def test_not_found(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["get_name_at"](0x999999) is None

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("get_name_at(0x401100)")
        assert result.ok
        assert result.output == "helper"


class TestDemangleName:
    """Test demangle_name()."""

    def test_mangled_name(self, mock_db):
        fns = _build_ida_functions(mock_db)
        result = fns["demangle_name"]("_Z3addii")
        assert result == "demangled(_Z3addii)"

    def test_unmangled_name(self, mock_db):
        fns = _build_ida_functions(mock_db)
        result = fns["demangle_name"]("main")
        assert result == "main"

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run('demangle_name("_Z3addii")')
        assert result.ok
        assert "demangled" in result.output


# ---------------------------------------------------------------------------
# New IDA function wrappers — imports & entries
# ---------------------------------------------------------------------------


class TestEnumerateImports:
    """Test enumerate_imports()."""

    def test_returns_all_imports(self, mock_db):
        fns = _build_ida_functions(mock_db)
        imports = fns["enumerate_imports"]()
        assert len(imports) == 2
        assert imports[0]["address"] == 0x404000
        assert imports[0]["name"] == "printf"
        assert imports[0]["module"] == "libc.so.6"
        assert imports[0]["ordinal"] == 0
        assert imports[1]["name"] == "__cxa_finalize"

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("len(enumerate_imports())")
        assert result.ok
        assert result.output == 2

    def test_via_sandbox_access_field(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run('enumerate_imports()[0]["name"]')
        assert result.ok
        assert result.output == "printf"


class TestEnumerateEntries:
    """Test enumerate_entries()."""

    def test_returns_all_entries(self, mock_db):
        fns = _build_ida_functions(mock_db)
        entries = fns["enumerate_entries"]()
        assert len(entries) == 1
        assert entries[0]["ordinal"] == 0
        assert entries[0]["address"] == 0x401060
        assert entries[0]["name"] == "_start"
        assert entries[0]["forwarder"] is None

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run('enumerate_entries()[0]["name"]')
        assert result.ok
        assert result.output == "_start"


# ---------------------------------------------------------------------------
# New IDA function wrappers — bytes / memory
# ---------------------------------------------------------------------------


class TestFindBytes:
    """Test find_bytes()."""

    def test_pattern_found(self, mock_db):
        fns = _build_ida_functions(mock_db)
        # bytes 0,1,2,3 start at offset 0 in our mock data (base 0x401000)
        addresses = fns["find_bytes"]([0, 1, 2, 3])
        assert 0x401000 in addresses

    def test_pattern_not_found(self, mock_db):
        fns = _build_ida_functions(mock_db)
        addresses = fns["find_bytes"]([0xFF, 0xFE, 0xFD])
        assert addresses == []

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("len(find_bytes([0, 1, 2, 3]))")
        assert result.ok
        assert result.output >= 1


class TestGetDisassemblyAt:
    """Test get_disassembly_at()."""

    def test_found(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["get_disassembly_at"](0x401000) == "push rbp"

    def test_not_found(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["get_disassembly_at"](0xDEAD) is None

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("get_disassembly_at(0x401000)")
        assert result.ok
        assert result.output == "push rbp"


class TestGetInstructionAt:
    """Test get_instruction_at()."""

    def test_found(self, mock_db):
        fns = _build_ida_functions(mock_db)
        insn = fns["get_instruction_at"](0x401000)
        assert insn is not None
        assert insn["address"] == 0x401000
        assert insn["size"] == 1
        assert insn["mnemonic"] == "push"
        assert insn["disassembly"] == "push rbp"
        assert insn["is_call"] is False

    def test_call_instruction(self, mock_db):
        fns = _build_ida_functions(mock_db)
        insn = fns["get_instruction_at"](0x401008)
        assert insn is not None
        assert insn["mnemonic"] == "call"
        assert insn["is_call"] is True

    def test_not_found(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["get_instruction_at"](0xDEAD) is None

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run(
            'insn = get_instruction_at(0x401000)\ninsn["mnemonic"]'
        )
        assert result.ok
        assert result.output == "push"

    def test_via_sandbox_is_call(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run(
            'insn = get_instruction_at(0x401008)\ninsn["is_call"]'
        )
        assert result.ok
        assert result.output is True


# ---------------------------------------------------------------------------
# New IDA function wrappers — address classification
# ---------------------------------------------------------------------------


class TestIsCodeAt:
    """Test is_code_at()."""

    def test_code_address(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["is_code_at"](0x401000) is True

    def test_non_code_address(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["is_code_at"](0x402000) is False

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("is_code_at(0x401000)")
        assert result.ok
        assert result.output is True


class TestIsDataAt:
    """Test is_data_at()."""

    def test_data_address(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["is_data_at"](0x402000) is True

    def test_non_data_address(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["is_data_at"](0x401000) is False

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("is_data_at(0x402000)")
        assert result.ok
        assert result.output is True


class TestIsValidAddress:
    """Test is_valid_address()."""

    def test_valid(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["is_valid_address"](0x401000) is True

    def test_invalid(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["is_valid_address"](0xDEAD) is False

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("is_valid_address(0x401000)")
        assert result.ok
        assert result.output is True

    def test_via_sandbox_invalid(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("is_valid_address(0xDEAD)")
        assert result.ok
        assert result.output is False


# ---------------------------------------------------------------------------
# New IDA function wrappers — comments
# ---------------------------------------------------------------------------


class TestGetCommentAt:
    """Test get_comment_at()."""

    def test_found(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["get_comment_at"](0x401000) == "function prologue"

    def test_not_found(self, mock_db):
        fns = _build_ida_functions(mock_db)
        assert fns["get_comment_at"](0x401100) is None

    def test_via_sandbox(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("get_comment_at(0x401000)")
        assert result.ok
        assert result.output == "function prologue"

    def test_via_sandbox_none(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run("get_comment_at(0x401100)")
        assert result.ok
        assert result.output is None


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

    def test_type_check_new_functions(self, mock_db):
        """Verify type checking passes for representative new function calls."""
        sandbox = IdaSandbox(mock_db, type_check=True)
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

    def test_type_check_catches_wrong_type_new_functions(self, mock_db):
        sandbox = IdaSandbox(mock_db, type_check=True)
        result = sandbox.run('get_function_by_name(42)')
        assert not result.ok
        assert result.error.kind == "typing"


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


# ---------------------------------------------------------------------------
# Comprehensive smoke test — exercises many new functions together
# ---------------------------------------------------------------------------


class TestComprehensiveScript:
    """Run a script that exercises all 28 sandbox functions end-to-end."""

    SCRIPT = """\
# Database metadata
info = get_binary_info()
print("Binary: " + info["module"] + " (" + info["architecture"] + ", " + str(info["bitness"]) + "-bit)")

# Function enumeration
functions = enumerate_functions()
print("Functions: " + str(len(functions)))

# Function lookup by name
main_fn = get_function_by_name("main")
print("main at: " + hex(main_fn["address"]))

# Decompile
pseudo = decompile_function(main_fn["address"])
print("Pseudocode lines: " + str(len(pseudo)))

# Signature
sig = get_function_signature(main_fn["address"])
print("Signature: " + str(sig))

# Callers & callees
helper_fn = get_function_by_name("helper")
callers = get_callers(helper_fn["address"])
print("Callers of helper: " + str(len(callers)))
callees = get_callees(main_fn["address"])
print("Callees of main: " + str(len(callees)))

# Basic blocks
blocks = get_basic_blocks(main_fn["address"])
print("Basic blocks in main: " + str(len(blocks)))

# Cross-references
xrefs_to = get_xrefs_to(helper_fn["address"])
print("Xrefs to helper: " + str(len(xrefs_to)))
xrefs_from = get_xrefs_from(0x401008)
print("Xrefs from 0x401008: " + str(len(xrefs_from)))

# Strings
strings = enumerate_strings()
print("Strings: " + str(len(strings)))
s = get_string_at(0x402000)
print("String at 0x402000: " + str(s))

# Segments
segments = enumerate_segments()
print("Segments: " + str(len(segments)))

# Names
names = enumerate_names()
print("Names: " + str(len(names)))
name = get_name_at(0x401000)
print("Name at 0x401000: " + str(name))
dm = demangle_name("_Z3addii")
print("Demangled: " + dm)

# Imports & entries
imports = enumerate_imports()
print("Imports: " + str(len(imports)))
entries = enumerate_entries()
print("Entries: " + str(len(entries)))

# Bytes
raw = read_bytes(0x401000, 4)
print("Bytes: " + str(raw))
found = find_bytes([0, 1, 2, 3])
print("Found pattern at " + str(len(found)) + " location(s)")

# Single instruction
disasm_line = get_disassembly_at(0x401000)
print("Disasm at 0x401000: " + str(disasm_line))
insn = get_instruction_at(0x401000)
print("Mnemonic: " + insn["mnemonic"])

# Address classification
print("Code at 0x401000: " + str(is_code_at(0x401000)))
print("Data at 0x402000: " + str(is_data_at(0x402000)))
print("Valid 0x401000: " + str(is_valid_address(0x401000)))
print("Valid 0xDEAD: " + str(is_valid_address(0xDEAD)))

# Comments
comment = get_comment_at(0x401000)
print("Comment: " + str(comment))

# Random
r = random_int(1, 100)
print("Random: " + str(r))
"""

    def test_comprehensive_script(self, mock_db):
        sandbox = IdaSandbox(mock_db)
        result = sandbox.run(self.SCRIPT)
        assert result.ok, f"Script failed: {result.error}"
        text = "".join(result.stdout)

        assert "Binary: binary (metapc, 64-bit)" in text
        assert "Functions: 3" in text
        assert "main at: 0x401000" in text
        assert "Pseudocode lines: 5" in text
        assert "Signature: int __cdecl main(void)" in text
        assert "Callers of helper: 1" in text
        assert "Callees of main: 2" in text
        assert "Basic blocks in main: 2" in text
        assert "Xrefs to helper: 1" in text
        assert "Xrefs from 0x401008: 1" in text
        assert "Strings: 2" in text
        assert "Hello" in text
        assert "Segments: 2" in text
        assert "Names: 4" in text
        assert "Name at 0x401000: main" in text
        assert "Demangled: demangled(_Z3addii)" in text
        assert "Imports: 2" in text
        assert "Entries: 1" in text
        assert "Bytes: [0, 1, 2, 3]" in text
        assert "Found pattern at" in text
        assert "Disasm at 0x401000: push rbp" in text
        assert "Mnemonic: push" in text
        assert "Code at 0x401000: True" in text
        assert "Data at 0x402000: True" in text
        assert "Valid 0x401000: True" in text
        assert "Valid 0xDEAD: False" in text
        assert "Comment: function prologue" in text
        assert "Random:" in text

    def test_comprehensive_script_with_type_check(self, mock_db):
        """Type-checked variant uses only non-Optional return values.

        Functions like get_function_by_name() and get_instruction_at()
        return Optional types, and monty's type checker does not support
        narrowing (``if x is not None``), so we test a subset that avoids
        subscripting optional results.
        """
        sandbox = IdaSandbox(mock_db, type_check=True)
        code = """\
info = get_binary_info()
print("arch: " + info["architecture"])
functions = enumerate_functions()
print("functions: " + str(len(functions)))
strings = enumerate_strings()
segments = enumerate_segments()
names = enumerate_names()
imports = enumerate_imports()
entries = enumerate_entries()
disasm = disassemble_function(0x401000)
print("disasm lines: " + str(len(disasm)))
xrefs = get_xrefs_to(0x401100)
print("xrefs: " + str(len(xrefs)))
raw = read_bytes(0x401000, 4)
print("bytes: " + str(raw))
found = find_bytes([0, 1, 2, 3])
print("found: " + str(len(found)))
print("code: " + str(is_code_at(0x401000)))
print("data: " + str(is_data_at(0x402000)))
print("valid: " + str(is_valid_address(0x401000)))
dm = demangle_name("main")
print("demangled: " + dm)
r = random_int(1, 100)
print("random: " + str(r))
"""
        result = sandbox.run(code)
        assert result.ok, f"Script failed with type check: {result.error}"
        text = "".join(result.stdout)
        assert "arch: metapc" in text
        assert "functions: 3" in text
