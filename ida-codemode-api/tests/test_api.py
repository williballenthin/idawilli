"""Tests for the ida-codemode-api package."""

from ida_codemode_api import (
    FUNCTION_NAMES,
    TYPE_STUBS,
    api_reference,
)


class TestFunctionNames:
    def test_is_list(self):
        assert isinstance(FUNCTION_NAMES, list)

    def test_has_26_functions(self):
        assert len(FUNCTION_NAMES) == 26

    def test_no_duplicates(self):
        assert len(FUNCTION_NAMES) == len(set(FUNCTION_NAMES))

    def test_all_strings(self):
        assert all(isinstance(name, str) for name in FUNCTION_NAMES)


class TestTypeStubs:
    def test_is_string(self):
        assert isinstance(TYPE_STUBS, str)

    def test_stubs_cover_all_functions(self):
        for name in FUNCTION_NAMES:
            assert f"def {name}(" in TYPE_STUBS, f"stub missing for {name}"

    def test_contains_typed_dicts(self):
        for typed_dict in [
            "class BinaryInfo(TypedDict)",
            "class FunctionInfo(TypedDict)",
            "class NamedAddress(TypedDict)",
            "class BasicBlockInfo(TypedDict)",
            "class XrefToInfo(TypedDict)",
            "class XrefFromInfo(TypedDict)",
            "class StringInfo(TypedDict)",
            "SegmentInfo = TypedDict(",
            "class ImportInfo(TypedDict)",
            "class EntryPointInfo(TypedDict)",
            "class InstructionInfo(TypedDict)",
        ]:
            assert typed_dict in TYPE_STUBS

    def test_parseable_python(self):
        compile(TYPE_STUBS, "<stubs>", "exec")


class TestApiReference:
    def test_returns_string(self):
        ref = api_reference()
        assert isinstance(ref, str)
        assert len(ref) > 100

    def test_contains_all_functions(self):
        ref = api_reference()
        for name in FUNCTION_NAMES:
            assert name in ref, f"api_reference missing: {name}"

    def test_single_table_layout(self):
        ref = api_reference()
        assert "| Function | Returns | Description |" in ref
        # One table header only.
        assert ref.count("| Function | Returns | Description |") == 1


class TestBuildIdaFunctions:
    def test_returns_dict(self, fns):
        assert isinstance(fns, dict)

    def test_has_all_functions(self, fns):
        for name in FUNCTION_NAMES:
            assert name in fns, f"missing function: {name}"
            assert callable(fns[name])

    def test_no_extra_functions(self, fns):
        assert set(fns.keys()) == set(FUNCTION_NAMES)


class TestBinaryInfo:
    def test_returns_dict(self, fns):
        info = fns["get_binary_info"]()
        assert isinstance(info, dict)

    def test_has_required_keys(self, fns):
        info = fns["get_binary_info"]()
        for key in [
            "path",
            "module",
            "architecture",
            "bitness",
            "format",
            "base_address",
            "entry_point",
            "minimum_ea",
            "maximum_ea",
            "filesize",
            "md5",
            "sha256",
            "crc32",
        ]:
            assert key in info, f"missing key: {key}"


class TestFunctionDiscovery:
    def test_get_functions_non_empty(self, fns):
        functions = fns["get_functions"]()
        assert len(functions) >= 1

    def test_function_dict_shape(self, fns):
        functions = fns["get_functions"]()
        for f in functions:
            assert "address" in f
            assert "name" in f
            assert "size" in f
            assert isinstance(f["address"], int)
            assert isinstance(f["name"], str)
            assert isinstance(f["size"], int)

    def test_lookup_by_name(self, fns):
        functions = fns["get_functions"]()
        name = functions[0]["name"]
        result = fns["get_function_by_name"](name)
        assert result is not None
        assert result["name"] == name

    def test_lookup_by_address(self, fns):
        functions = fns["get_functions"]()
        address = functions[0]["address"]
        result = fns["get_function_at"](address)
        assert result is not None
        assert result["address"] == address


class TestFunctionAnalysis:
    def test_disassembly(self, fns, first_func):
        lines = fns["get_function_disassembly_at"](first_func["address"])
        assert isinstance(lines, list)
        assert len(lines) >= 1
        assert all(isinstance(line, str) for line in lines)

    def test_disassembly_bad_address(self, fns):
        lines = fns["get_function_disassembly_at"](0xDEADDEAD)
        assert lines == []

    def test_decompile_no_crash(self, fns, first_func):
        lines = fns["decompile_function_at"](first_func["address"])
        assert isinstance(lines, list)
        assert all(isinstance(line, str) for line in lines)

    def test_signature(self, fns, first_func):
        sig = fns["get_function_signature_at"](first_func["address"])
        assert sig is None or isinstance(sig, str)

    def test_callers_shape(self, fns, first_func):
        callers = fns["get_callers_at"](first_func["address"])
        assert isinstance(callers, list)
        for c in callers:
            assert "address" in c
            assert "name" in c

    def test_callees_shape(self, fns, first_func):
        callees = fns["get_callees_at"](first_func["address"])
        assert isinstance(callees, list)
        for c in callees:
            assert "address" in c
            assert "name" in c

    def test_basic_blocks_shape(self, fns, first_func):
        blocks = fns["get_basic_blocks_at"](first_func["address"])
        assert isinstance(blocks, list)
        for b in blocks:
            assert "start" in b
            assert "end" in b
            assert "successors" in b
            assert "predecessors" in b


class TestXrefs:
    def test_xrefs_to_shape(self, fns, first_func):
        xrefs = fns["get_xrefs_to_at"](first_func["address"])
        assert isinstance(xrefs, list)
        for x in xrefs:
            assert "from_address" in x
            assert "type" in x
            assert "is_call" in x
            assert "is_jump" in x

    def test_xrefs_from_shape(self, fns, first_func):
        xrefs = fns["get_xrefs_from_at"](first_func["address"])
        assert isinstance(xrefs, list)
        for x in xrefs:
            assert "to_address" in x
            assert "type" in x
            assert "is_call" in x
            assert "is_jump" in x


class TestStrings:
    def test_get_strings_non_empty(self, fns):
        strings = fns["get_strings"]()
        assert len(strings) >= 1

    def test_get_string_at_no_crash(self, fns):
        strings = fns["get_strings"]()
        result = fns["get_string_at"](strings[0]["address"])
        assert result is None or isinstance(result, str)


class TestSegments:
    def test_get_segments_non_empty(self, fns):
        segs = fns["get_segments"]()
        assert len(segs) >= 1

    def test_segment_shape(self, fns):
        segs = fns["get_segments"]()
        for s in segs:
            assert "name" in s
            assert "start" in s
            assert "end" in s
            assert "size" in s
            assert "permissions" in s
            assert "class" in s
            assert "bitness" in s


class TestNames:
    def test_get_names_non_empty(self, fns):
        names = fns["get_names"]()
        assert len(names) >= 1

    def test_get_name_at(self, fns, first_func):
        name = fns["get_name_at"](first_func["address"])
        assert name is None or isinstance(name, str)

    def test_demangle_passthrough(self, fns):
        assert fns["demangle_name"]("main") == "main"


class TestImportsAndEntries:
    def test_imports_shape(self, fns):
        imports = fns["get_imports"]()
        assert isinstance(imports, list)
        for imp in imports:
            assert "address" in imp
            assert "name" in imp
            assert "module" in imp
            assert "ordinal" in imp

    def test_entries_shape(self, fns):
        entries = fns["get_entries"]()
        assert isinstance(entries, list)
        for e in entries:
            assert "ordinal" in e
            assert "address" in e
            assert "name" in e
            assert "forwarder" in e


class TestBytesAndMemory:
    def test_get_bytes_at(self, fns, first_func):
        raw = fns["get_bytes_at"](first_func["address"], 4)
        assert isinstance(raw, list)
        assert len(raw) == 4
        assert all(isinstance(b, int) and 0 <= b <= 255 for b in raw)

    def test_find_bytes(self, fns, first_func):
        raw = fns["get_bytes_at"](first_func["address"], 3)
        hits = fns["find_bytes"](raw)
        assert isinstance(hits, list)

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
        assert text is None or isinstance(text, str)


class TestAddressType:
    def test_code_address(self, fns, first_func):
        assert fns["get_address_type"](first_func["address"]) in {
            "code",
            "data",
            "unknown",
            "invalid",
        }

    def test_invalid_address(self, fns):
        assert fns["get_address_type"](0xDEADDEAD) == "invalid"


class TestComments:
    def test_get_comment_no_crash(self, fns, first_func):
        result = fns["get_comment_at"](first_func["address"])
        assert result is None or isinstance(result, str)
