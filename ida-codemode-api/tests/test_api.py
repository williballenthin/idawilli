"""Tests for the ida-codemode-api package.

Two layers:

  Layer 1 — API contract (no IDA):
    Verify FUNCTION_NAMES, TYPE_STUBS, and api_reference() are consistent.

  Layer 2 — IDA-backed functions (direct calls):
    Verify each function in build_ida_functions() returns correctly shaped
    data from real IDA analysis.
"""

from ida_codemode_api import (
    FUNCTION_NAMES,
    TYPE_STUBS,
    api_reference,
)


# ===========================================================================
# Layer 1 — API contract (no IDA required)
# ===========================================================================


class TestFunctionNames:
    """Verify FUNCTION_NAMES is well-formed."""

    def test_is_list(self):
        assert isinstance(FUNCTION_NAMES, list)

    def test_has_28_functions(self):
        assert len(FUNCTION_NAMES) == 28

    def test_no_duplicates(self):
        assert len(FUNCTION_NAMES) == len(set(FUNCTION_NAMES))

    def test_all_strings(self):
        for name in FUNCTION_NAMES:
            assert isinstance(name, str)


class TestTypeStubs:
    """Verify TYPE_STUBS covers all functions."""

    def test_is_string(self):
        assert isinstance(TYPE_STUBS, str)

    def test_stubs_cover_all_functions(self):
        for name in FUNCTION_NAMES:
            assert f"def {name}(" in TYPE_STUBS, f"stub missing for {name}"

    def test_parseable_python(self):
        compile(TYPE_STUBS, "<stubs>", "exec")


class TestApiReference:
    """Verify api_reference() returns complete documentation."""

    def test_returns_string(self):
        ref = api_reference()
        assert isinstance(ref, str)
        assert len(ref) > 100

    def test_contains_all_functions(self):
        ref = api_reference()
        for name in FUNCTION_NAMES:
            assert name in ref, f"api_reference missing: {name}"

    def test_contains_all_categories(self):
        ref = api_reference()
        for category in [
            "Database metadata",
            "Functions",
            "Cross-references",
            "Strings",
            "Segments",
            "Names / symbols",
            "Imports and entries",
            "Bytes / memory",
            "Address classification",
            "Comments",
            "Utilities",
        ]:
            assert category in ref, f"api_reference missing category: {category}"


# ===========================================================================
# Layer 2 — IDA-backed functions (direct calls against real DB)
# ===========================================================================


class TestBuildIdaFunctions:
    """Verify build_ida_functions returns the right shape."""

    def test_returns_dict(self, fns):
        assert isinstance(fns, dict)

    def test_has_all_functions(self, fns):
        for name in FUNCTION_NAMES:
            assert name in fns, f"missing function: {name}"
            assert callable(fns[name])

    def test_no_extra_functions(self, fns):
        assert set(fns.keys()) == set(FUNCTION_NAMES)


class TestBinaryInfo:
    """get_binary_info()."""

    def test_returns_dict(self, fns):
        info = fns["get_binary_info"]()
        assert isinstance(info, dict)

    def test_has_required_keys(self, fns):
        info = fns["get_binary_info"]()
        for key in ["path", "module", "architecture", "bitness", "format",
                     "base_address", "entry_point", "minimum_ea", "maximum_ea",
                     "filesize", "md5", "sha256", "crc32"]:
            assert key in info, f"missing key: {key}"

    def test_architecture_is_metapc(self, fns):
        info = fns["get_binary_info"]()
        assert info["architecture"] == "metapc"

    def test_bitness_is_32(self, fns):
        info = fns["get_binary_info"]()
        assert info["bitness"] == 32


class TestFunctionEnumeration:
    """enumerate_functions(), get_function_by_name()."""

    def test_enumerate_non_empty(self, fns):
        functions = fns["enumerate_functions"]()
        assert len(functions) >= 1

    def test_function_dict_shape(self, fns):
        functions = fns["enumerate_functions"]()
        for f in functions:
            assert "address" in f
            assert "name" in f
            assert "size" in f
            assert isinstance(f["address"], int)
            assert isinstance(f["name"], str)
            assert isinstance(f["size"], int)

    def test_lookup_by_name(self, fns):
        functions = fns["enumerate_functions"]()
        name = functions[0]["name"]
        result = fns["get_function_by_name"](name)
        assert result is not None
        assert result["name"] == name

    def test_lookup_nonexistent(self, fns):
        result = fns["get_function_by_name"]("__nonexistent_xyz__")
        assert result is None


class TestFunctionAnalysis:
    """disassemble, decompile, signature, callers, callees, basic_blocks."""

    def test_disassemble(self, fns, first_func):
        lines = fns["disassemble_function"](first_func["address"])
        assert isinstance(lines, list)
        assert len(lines) >= 1
        assert all(isinstance(line, str) for line in lines)

    def test_disassemble_bad_address(self, fns):
        lines = fns["disassemble_function"](0xDEADDEAD)
        assert lines == []

    def test_signature(self, fns, first_func):
        sig = fns["get_function_signature"](first_func["address"])
        # May or may not have a signature, but shouldn't crash
        assert sig is None or isinstance(sig, str)

    def test_callers_shape(self, fns, first_func):
        callers = fns["get_callers"](first_func["address"])
        assert isinstance(callers, list)
        for c in callers:
            assert "address" in c
            assert "name" in c

    def test_callees_shape(self, fns, first_func):
        callees = fns["get_callees"](first_func["address"])
        assert isinstance(callees, list)
        for c in callees:
            assert "address" in c
            assert "name" in c

    def test_basic_blocks(self, fns, first_func):
        blocks = fns["get_basic_blocks"](first_func["address"])
        assert isinstance(blocks, list)
        assert len(blocks) >= 1
        for b in blocks:
            assert "start" in b
            assert "end" in b
            assert "successors" in b
            assert "predecessors" in b


class TestXrefs:
    """get_xrefs_to(), get_xrefs_from()."""

    def test_xrefs_to_shape(self, fns, first_func):
        xrefs = fns["get_xrefs_to"](first_func["address"])
        assert isinstance(xrefs, list)
        for x in xrefs:
            assert "from_address" in x
            assert "type" in x
            assert "is_call" in x
            assert "is_jump" in x

    def test_xrefs_from_shape(self, fns, first_func):
        xrefs = fns["get_xrefs_from"](first_func["address"])
        assert isinstance(xrefs, list)
        for x in xrefs:
            assert "to_address" in x
            assert "type" in x

    def test_bad_address(self, fns):
        assert fns["get_xrefs_to"](0xDEADDEAD) == []
        assert fns["get_xrefs_from"](0xDEADDEAD) == []


class TestStrings:
    """enumerate_strings(), get_string_at()."""

    def test_enumerate_non_empty(self, fns):
        strings = fns["enumerate_strings"]()
        assert len(strings) >= 1

    def test_string_dict_shape(self, fns):
        strings = fns["enumerate_strings"]()
        for s in strings:
            assert "address" in s
            assert "length" in s
            assert "type" in s
            assert "value" in s


class TestSegments:
    """enumerate_segments()."""

    def test_enumerate_non_empty(self, fns):
        segments = fns["enumerate_segments"]()
        assert len(segments) >= 1

    def test_has_code_segment(self, fns):
        segments = fns["enumerate_segments"]()
        classes = [s["class"] for s in segments]
        assert "CODE" in classes


class TestNames:
    """enumerate_names(), get_name_at(), demangle_name()."""

    def test_enumerate_non_empty(self, fns):
        names = fns["enumerate_names"]()
        assert len(names) >= 1

    def test_get_name_at(self, fns, first_func):
        name = fns["get_name_at"](first_func["address"])
        assert name is not None
        assert isinstance(name, str)

    def test_get_name_at_bad_address(self, fns):
        assert fns["get_name_at"](0xDEADDEAD) is None

    def test_demangle_passthrough(self, fns):
        result = fns["demangle_name"]("main")
        assert result == "main"


class TestImportsAndEntries:
    """enumerate_imports(), enumerate_entries()."""

    def test_imports_non_empty(self, fns):
        imports = fns["enumerate_imports"]()
        assert len(imports) >= 1

    def test_import_dict_shape(self, fns):
        imports = fns["enumerate_imports"]()
        for imp in imports:
            assert "address" in imp
            assert "name" in imp
            assert "module" in imp
            assert "ordinal" in imp

    def test_entries_non_empty(self, fns):
        entries = fns["enumerate_entries"]()
        assert len(entries) >= 1


class TestBytesAndMemory:
    """read_bytes(), find_bytes(), get_disassembly_at(), get_instruction_at()."""

    def test_read_bytes(self, fns, first_func):
        raw = fns["read_bytes"](first_func["address"], 4)
        assert isinstance(raw, list)
        assert len(raw) == 4
        assert all(isinstance(b, int) and 0 <= b <= 255 for b in raw)

    def test_read_bytes_bad_address(self, fns):
        assert fns["read_bytes"](0xDEADDEAD, 4) == []

    def test_get_instruction_at(self, fns, first_func):
        insn = fns["get_instruction_at"](first_func["address"])
        assert insn is not None
        assert "address" in insn
        assert "size" in insn
        assert "mnemonic" in insn
        assert "disassembly" in insn
        assert "is_call" in insn

    def test_get_disassembly_at(self, fns, first_func):
        text = fns["get_disassembly_at"](first_func["address"])
        assert text is not None
        assert isinstance(text, str)


class TestAddressClassification:
    """is_code_at(), is_data_at(), is_valid_address()."""

    def test_code_at_function(self, fns, first_func):
        assert fns["is_code_at"](first_func["address"]) is True

    def test_valid_address(self, fns, first_func):
        assert fns["is_valid_address"](first_func["address"]) is True

    def test_invalid_address(self, fns):
        assert fns["is_valid_address"](0xDEADDEAD) is False


class TestComments:
    """get_comment_at()."""

    def test_no_crash(self, fns, first_func):
        result = fns["get_comment_at"](first_func["address"])
        assert result is None or isinstance(result, str)

    def test_bad_address(self, fns):
        assert fns["get_comment_at"](0xDEADDEAD) is None


class TestRandomInt:
    """random_int()."""

    def test_in_range(self, fns):
        for _ in range(10):
            val = fns["random_int"](1, 100)
            assert 1 <= val <= 100
