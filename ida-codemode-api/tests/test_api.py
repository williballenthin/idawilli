"""Tests for the ida-codemode-api package."""

import inspect
import re

import pytest

from ida_codemode_api import (
    FUNCTION_NAMES,
    TYPE_STUBS,
    api_reference,
    create_api_from_database,
)
from ida_codemode_api import api_types
from ida_codemode_api.api import TYPE_STUBS_PATH


def assert_ok(result):
    assert isinstance(result, dict)
    if "error" in result:
        pytest.fail(f"expected success result, got error: {result['error']}")
    return result


def assert_keys_exact(result: dict[str, object], expected_keys: set[str]):
    assert set(result.keys()) == expected_keys


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

    def test_contains_core_typed_dicts(self):
        for typed_dict in [
            "class DatabaseMetadata(TypedDict)",
            "class FunctionInfo(TypedDict)",
            "class NamedAddress(TypedDict)",
            "class ApiError(TypedDict)",
            "class GetFunctionsOk(TypedDict)",
            "class GetAddressTypeOk(TypedDict)",
        ]:
            assert typed_dict in TYPE_STUBS

    def test_contains_error_key_contract(self):
        assert "error: str" in TYPE_STUBS
        assert 'Status: Literal["okay"]' not in TYPE_STUBS
        assert 'Status: Literal["error"]' not in TYPE_STUBS

    def test_parseable_python(self):
        compile(TYPE_STUBS, "<stubs>", "exec")

    def test_matches_authoritative_file(self):
        assert TYPE_STUBS == TYPE_STUBS_PATH.read_text(encoding="utf-8")


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
        assert ref.count("| Function | Returns | Description |") == 1

    def test_mentions_global_error_contract(self):
        ref = api_reference()
        assert "{error: str}" in ref
        assert "presence of the `error` key" in ref



class TestApiDocstrings:
    def test_api_types_docstrings_have_required_sections(self):
        for name in FUNCTION_NAMES:
            declaration = getattr(api_types, name)
            doc = inspect.getdoc(declaration)
            assert doc, f"missing docstring for api_types.{name}"

            first_line = doc.splitlines()[0].strip()
            assert first_line
            assert first_line[0].isupper()
            assert first_line.endswith(".")

            assert re.search(r"See\s+also", doc), (
                f"api_types.{name} docstring missing 'See also'"
            )
            assert "Returns:" in doc, f"api_types.{name} docstring missing 'Returns:'"
            assert "Errors:" in doc, f"api_types.{name} docstring missing 'Errors:'"
            assert (
                "Example success payload:" in doc
            ), f"api_types.{name} docstring missing example payload"

            if inspect.signature(declaration).parameters:
                assert "Args:" in doc, f"api_types.{name} docstring missing 'Args:'"

    def test_runtime_docstrings_removed_for_exported_api(self):
        runtime_api = create_api_from_database(object())
        for name in FUNCTION_NAMES:
            runtime_fn = runtime_api[name]
            assert inspect.getdoc(runtime_fn) is None

    def test_api_reference_prefers_api_types_docstrings(self):
        ref = api_reference()

        rows: dict[str, str] = {}
        row_pattern = re.compile(r"^\| `([^`]*)` \| `([^`]*)` \| (.*) \|$")

        for line in ref.splitlines():
            match = row_pattern.match(line)
            if not match:
                continue

            signature = match.group(1)
            description = match.group(3)
            function_name = signature.split("(", 1)[0]
            rows[function_name] = description

        for name in FUNCTION_NAMES:
            declaration = getattr(api_types, name)
            declaration_doc = inspect.getdoc(declaration)
            assert declaration_doc, f"missing declaration docstring for {name}"

            first_line = declaration_doc.splitlines()[0].strip()
            assert rows.get(name) == first_line


class TestPayloadContracts:
    def test_success_payload_top_level_keys(self, fns, first_func):
        functions_result = assert_ok(fns["get_functions"]())
        functions = functions_result["functions"]
        first = first_func
        strings_result = assert_ok(fns["get_strings"]())
        strings = strings_result["strings"]
        string_address = strings[0]["address"] if strings else first["address"]

        raw_bytes = assert_ok(fns["get_bytes_at"](first["address"], 4))["bytes"]

        payloads = {
            "help": assert_ok(fns["help"]("get_functions")),
            "get_database_metadata": assert_ok(fns["get_database_metadata"]()),
            "get_functions": functions_result,
            "get_function_by_name": assert_ok(fns["get_function_by_name"](first["name"])),
            "get_function_at": assert_ok(fns["get_function_at"](first["address"])),
            "get_function_disassembly_at": assert_ok(fns["get_function_disassembly_at"](first["address"])),
            "get_function_callers": assert_ok(fns["get_function_callers"](first["address"])),
            "get_function_callees": assert_ok(fns["get_function_callees"](first["address"])),
            "get_basic_blocks_at": assert_ok(fns["get_basic_blocks_at"](first["address"])),
            "get_xrefs_to_at": assert_ok(fns["get_xrefs_to_at"](first["address"])),
            "get_xrefs_from_at": assert_ok(fns["get_xrefs_from_at"](first["address"])),
            "get_strings": strings_result,
            "get_segments": assert_ok(fns["get_segments"]()),
            "get_names": assert_ok(fns["get_names"]()),
            "demangle_name": assert_ok(fns["demangle_name"]("main")),
            "get_imports": assert_ok(fns["get_imports"]()),
            "get_entries": assert_ok(fns["get_entries"]()),
            "get_bytes_at": {"bytes": raw_bytes},
            "find_bytes": assert_ok(fns["find_bytes"](raw_bytes)),
            "get_disassembly_at": assert_ok(fns["get_disassembly_at"](first["address"])),
            "get_instruction_at": assert_ok(fns["get_instruction_at"](first["address"])),
            "get_address_type": assert_ok(fns["get_address_type"](first["address"])),
        }

        expected_keys = {
            "help": {"documentation"},
            "get_database_metadata": {
                "input_file_path",
                "module",
                "architecture",
                "bitness",
                "format",
                "base_address",
                "entry_point",
                "minimum_ea",
                "maximum_ea",
                "input_file_size",
                "input_file_md5",
                "input_file_sha256",
            },
            "get_functions": {"functions"},
            "get_function_by_name": {"address", "name", "size", "signature", "flags", "comment", "repeatable_comment"},
            "get_function_at": {"address", "name", "size", "signature", "flags", "comment", "repeatable_comment"},
            "get_function_disassembly_at": {"disassembly"},
            "get_function_callers": {"callers"},
            "get_function_callees": {"callees"},
            "get_basic_blocks_at": {"basic_blocks"},
            "get_xrefs_to_at": {"xrefs"},
            "get_xrefs_from_at": {"xrefs"},
            "get_strings": {"strings"},
            "get_segments": {"segments"},
            "get_names": {"names"},
            "demangle_name": {"demangled_name"},
            "get_imports": {"imports"},
            "get_entries": {"entries"},
            "get_bytes_at": {"bytes"},
            "find_bytes": {"addresses"},
            "get_disassembly_at": {"disassembly"},
            "get_instruction_at": {
                "address",
                "size",
                "mnemonic",
                "disassembly",
                "is_call",
            },
            "get_address_type": {"address_type"},
        }

        for function_name, payload in payloads.items():
            assert_keys_exact(payload, expected_keys[function_name])

        if functions:
            assert_keys_exact(functions[0], {"address", "name", "size", "signature", "flags", "comment", "repeatable_comment"})

        if payloads["get_function_callers"]["callers"]:
            assert_keys_exact(payloads["get_function_callers"]["callers"][0], {"address", "name", "size", "signature", "flags", "comment", "repeatable_comment"})

        if payloads["get_function_callees"]["callees"]:
            assert_keys_exact(payloads["get_function_callees"]["callees"][0], {"address", "name", "size", "signature", "flags", "comment", "repeatable_comment"})

        if payloads["get_xrefs_to_at"]["xrefs"]:
            assert_keys_exact(
                payloads["get_xrefs_to_at"]["xrefs"][0],
                {"from_address", "type", "is_call", "is_jump"},
            )

        if payloads["get_xrefs_from_at"]["xrefs"]:
            assert_keys_exact(
                payloads["get_xrefs_from_at"]["xrefs"][0],
                {"to_address", "type", "is_call", "is_jump"},
            )

        if strings:
            assert_keys_exact(strings[0], {"address", "length", "type", "value"})

        optional_calls = {
            "decompile_function_at": fns["decompile_function_at"](first["address"]),
            "get_string_at": fns["get_string_at"](string_address),
            "get_name_at": fns["get_name_at"](first["address"]),
            "get_comment_at": fns["get_comment_at"](first["address"]),
        }
        optional_expected_keys = {
            "decompile_function_at": {"pseudocode"},
            "get_string_at": {"string"},
            "get_name_at": {"name"},
            "get_comment_at": {"comment"},
        }

        for function_name, result in optional_calls.items():
            if "error" in result:
                assert isinstance(result["error"], str)
            else:
                assert_keys_exact(result, optional_expected_keys[function_name])


class TestBuildIdaFunctions:
    def test_returns_dict(self, fns):
        assert isinstance(fns, dict)

    def test_has_all_functions(self, fns):
        for name in FUNCTION_NAMES:
            assert name in fns, f"missing function: {name}"
            assert callable(fns[name])

    def test_no_extra_functions(self, fns):
        assert set(fns.keys()) == set(FUNCTION_NAMES)


class TestDatabaseMetadata:
    def test_returns_success_shape(self, fns):
        info = fns["get_database_metadata"]()
        assert_ok(info)

    def test_has_required_keys(self, fns):
        info = assert_ok(fns["get_database_metadata"]())
        for key in [
            "input_file_path",
            "module",
            "architecture",
            "bitness",
            "format",
            "base_address",
            "entry_point",
            "minimum_ea",
            "maximum_ea",
            "input_file_size",
            "input_file_md5",
            "input_file_sha256",
        ]:
            assert key in info, f"missing key: {key}"


class TestFunctionDiscovery:
    def test_get_functions_non_empty(self, fns):
        functions = assert_ok(fns["get_functions"]())["functions"]
        assert len(functions) >= 1

    def test_function_dict_shape(self, fns):
        functions = assert_ok(fns["get_functions"]())["functions"]
        for f in functions:
            assert "address" in f
            assert "name" in f
            assert "size" in f
            assert "signature" in f
            assert "flags" in f
            assert "comment" in f
            assert "repeatable_comment" in f
            assert isinstance(f["address"], int)
            assert isinstance(f["name"], str)
            assert isinstance(f["size"], int)
            assert isinstance(f["signature"], str)
            assert isinstance(f["flags"], dict)
            assert isinstance(f["comment"], str)
            assert isinstance(f["repeatable_comment"], str)
            assert "noreturn" in f["flags"]
            assert "library" in f["flags"]
            assert "thunk" in f["flags"]

    def test_lookup_by_name(self, fns):
        functions = assert_ok(fns["get_functions"]())["functions"]
        name = functions[0]["name"]
        result = assert_ok(fns["get_function_by_name"](name))
        assert result["name"] == name

    def test_lookup_by_address(self, fns):
        functions = assert_ok(fns["get_functions"]())["functions"]
        address = functions[0]["address"]
        result = assert_ok(fns["get_function_at"](address))
        assert result["address"] == address


class TestFunctionAnalysis:
    def test_disassembly(self, fns, first_func):
        lines = assert_ok(fns["get_function_disassembly_at"](first_func["address"]))["disassembly"]
        assert isinstance(lines, list)
        assert len(lines) >= 1
        assert all(isinstance(line, str) for line in lines)

    def test_disassembly_bad_address(self, fns):
        result = fns["get_function_disassembly_at"](0xDEADDEAD)
        assert "error" in result
        assert isinstance(result["error"], str)

    def test_decompile_no_crash(self, fns, first_func):
        result = fns["decompile_function_at"](first_func["address"])
        if "error" in result:
            assert isinstance(result["error"], str)
        else:
            assert all(isinstance(line, str) for line in result["pseudocode"])

    def test_callers_shape(self, fns, first_func):
        callers = assert_ok(fns["get_function_callers"](first_func["address"]))["callers"]
        assert isinstance(callers, list)
        for c in callers:
            assert "address" in c
            assert "name" in c
            assert "size" in c
            assert "signature" in c
            assert "flags" in c
            assert "comment" in c
            assert "repeatable_comment" in c

    def test_callees_shape(self, fns, first_func):
        callees = assert_ok(fns["get_function_callees"](first_func["address"]))["callees"]
        assert isinstance(callees, list)
        for c in callees:
            assert "address" in c
            assert "name" in c
            assert "size" in c
            assert "signature" in c
            assert "flags" in c
            assert "comment" in c
            assert "repeatable_comment" in c

    def test_basic_blocks_shape(self, fns, first_func):
        blocks = assert_ok(fns["get_basic_blocks_at"](first_func["address"]))["basic_blocks"]
        assert isinstance(blocks, list)
        for b in blocks:
            assert "start" in b
            assert "end" in b
            assert "successors" in b
            assert "predecessors" in b


class TestXrefs:
    def test_xrefs_to_shape(self, fns, first_func):
        xrefs = assert_ok(fns["get_xrefs_to_at"](first_func["address"]))["xrefs"]
        assert isinstance(xrefs, list)
        for x in xrefs:
            assert "from_address" in x
            assert "type" in x
            assert "is_call" in x
            assert "is_jump" in x

    def test_xrefs_from_shape(self, fns, first_func):
        xrefs = assert_ok(fns["get_xrefs_from_at"](first_func["address"]))["xrefs"]
        assert isinstance(xrefs, list)
        for x in xrefs:
            assert "to_address" in x
            assert "type" in x
            assert "is_call" in x
            assert "is_jump" in x


class TestStrings:
    def test_get_strings_non_empty(self, fns):
        strings = assert_ok(fns["get_strings"]())["strings"]
        assert len(strings) >= 1

    def test_get_string_at_no_crash(self, fns):
        strings = assert_ok(fns["get_strings"]())["strings"]
        result = fns["get_string_at"](strings[0]["address"])
        assert "error" in result or "string" in result


class TestSegments:
    def test_get_segments_non_empty(self, fns):
        segs = assert_ok(fns["get_segments"]())["segments"]
        assert len(segs) >= 1

    def test_segment_shape(self, fns):
        segs = assert_ok(fns["get_segments"]())["segments"]
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
        names = assert_ok(fns["get_names"]())["names"]
        assert len(names) >= 1

    def test_get_name_at(self, fns, first_func):
        result = fns["get_name_at"](first_func["address"])
        assert "error" in result or "name" in result

    def test_demangle_passthrough(self, fns):
        result = assert_ok(fns["demangle_name"]("main"))
        assert result["demangled_name"] == "main"


class TestImportsAndEntries:
    def test_imports_shape(self, fns):
        imports = assert_ok(fns["get_imports"]())["imports"]
        assert isinstance(imports, list)
        for imp in imports:
            assert "address" in imp
            assert "name" in imp
            assert "module" in imp
            assert "ordinal" in imp

    def test_entries_shape(self, fns):
        entries = assert_ok(fns["get_entries"]())["entries"]
        assert isinstance(entries, list)
        for e in entries:
            assert "ordinal" in e
            assert "address" in e
            assert "name" in e
            assert "forwarder" in e


class TestBytesAndMemory:
    def test_get_bytes_at(self, fns, first_func):
        raw = assert_ok(fns["get_bytes_at"](first_func["address"], 4))["bytes"]
        assert isinstance(raw, list)
        assert len(raw) == 4
        assert all(isinstance(b, int) and 0 <= b <= 255 for b in raw)

    def test_find_bytes(self, fns, first_func):
        raw = assert_ok(fns["get_bytes_at"](first_func["address"], 3))["bytes"]
        hits = assert_ok(fns["find_bytes"](raw))["addresses"]
        assert isinstance(hits, list)

    def test_get_instruction_at(self, fns, first_func):
        insn = assert_ok(fns["get_instruction_at"](first_func["address"]))
        assert "address" in insn
        assert "size" in insn
        assert "mnemonic" in insn
        assert "disassembly" in insn
        assert "is_call" in insn

    def test_get_disassembly_at(self, fns, first_func):
        text = assert_ok(fns["get_disassembly_at"](first_func["address"]))["disassembly"]
        assert isinstance(text, str)


class TestAddressType:
    def test_code_address(self, fns, first_func):
        result = assert_ok(fns["get_address_type"](first_func["address"]))
        assert result["address_type"] in {
            "code",
            "data",
            "unknown",
            "invalid",
        }

    def test_invalid_address(self, fns):
        result = assert_ok(fns["get_address_type"](0xDEADDEAD))
        assert result["address_type"] == "invalid"


class TestComments:
    def test_get_comment_no_crash(self, fns, first_func):
        result = fns["get_comment_at"](first_func["address"])
        assert "error" in result or "comment" in result


class TestHelp:
    def test_help_known_callback(self, fns):
        result = assert_ok(fns["help"]("get_function_at"))
        text = result["documentation"]

        assert isinstance(text, str)
        assert "get_function_at" in text
        assert "Returns:" in text

    def test_help_unknown_callback(self, fns):
        result = fns["help"]("definitely_not_a_callback")
        assert "error" in result
        assert isinstance(result["error"], str)
