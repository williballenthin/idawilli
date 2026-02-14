"""Tests for the ida-codemode-api package."""

import inspect
import re
from typing import get_type_hints

import pytest

from ida_codemode_api import (
    FUNCTION_NAMES,
    TYPE_STUBS,
    api_reference,
    create_api_from_database,
)
from ida_codemode_api import api_types
from ida_codemode_api.api import (
    TYPE_STUBS_PATH,
    _render_type,
    read_ascii_string_at,
    read_utf16le_string_at,
    read_string_at,
)


def assert_ok(result):
    assert isinstance(result, dict)
    if "error" in result:
        pytest.fail(f"expected success result, got error: {result['error']}")
    return result


def assert_mutator_success(result):
    if result is None:
        return
    if isinstance(result, dict) and "error" not in result:
        pytest.fail(f"mutator returned non-None success value: {result}")
    if isinstance(result, dict) and "error" in result:
        pytest.fail(f"expected mutator success (None), got error: {result['error']}")
    pytest.fail(f"mutator returned unexpected value: {result}")


def assert_keys_exact(result: dict[str, object], expected_keys: set[str]):
    assert set(result.keys()) == expected_keys


class TestFunctionNames:
    def test_is_list(self):
        assert isinstance(FUNCTION_NAMES, list)

    def test_has_38_functions(self):
        assert len(FUNCTION_NAMES) == 38

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

    def test_contains_api_function_contract(self):
        assert "class ApiFunctions(TypedDict):" in TYPE_STUBS
        assert "SetTypeAtFn = Callable[[int, str], SetTypeAtResult]" in TYPE_STUBS
        assert "GetFunctionsFn = Callable[[], GetFunctionsResult]" in TYPE_STUBS

    def test_contains_error_key_contract(self):
        assert "error: str" in TYPE_STUBS
        assert 'Status: Literal["okay"]' not in TYPE_STUBS
        assert 'Status: Literal["error"]' not in TYPE_STUBS

    def test_parseable_python(self):
        compile(TYPE_STUBS, "<stubs>", "exec")

    def test_matches_authoritative_file(self):
        assert TYPE_STUBS == TYPE_STUBS_PATH.read_text(encoding="utf-8")


class TestRenderType:
    def test_renders_none_type(self):
        assert _render_type(type(None)) == "None"

    def test_renders_none_or_api_error_union(self):
        result = _render_type(None | api_types.ApiError)
        assert result == "None"

    def test_renders_mutator_result_alias(self):
        assert _render_type(api_types.MutatorResult) == "None"


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
        assert "expect_ok(result)" in ref
        assert "prefer `expect_ok(...)`" in ref

    def test_mentions_mutator_convention(self):
        ref = api_reference()
        assert "Mutation functions return `None` on success" in ref

    def test_uses_declaration_signatures(self):
        ref = api_reference()
        assert "`set_type_at(address: int, type: str)`" in ref
        assert "`set_local_variable_type(function_address: int, existing_name: str, type: str)`" in ref
        assert "type_str" not in ref


class TestApiDocstrings:
    def test_api_types_docstrings_have_required_sections(self):
        mutator_functions = {"set_name_at", "set_type_at", "set_comment_at", "set_repeatable_comment_at", "add_bookmark", "delete_bookmark", "set_local_variable_name", "set_local_variable_type"}

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

            if name not in mutator_functions:
                assert (
                    "Example success payload:" in doc
                ), f"api_types.{name} docstring missing example payload"

            if inspect.signature(declaration).parameters:
                assert "Args:" in doc, f"api_types.{name} docstring missing 'Args:'"

    def test_runtime_docstrings_removed_for_exported_api(self):
        runtime_api = create_api_from_database(object())
        assert set(runtime_api.keys()) == set(FUNCTION_NAMES)
        for runtime_fn in runtime_api.values():
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
            "get_function_data_xrefs": assert_ok(fns["get_function_data_xrefs"](first["address"])),
            "get_function_string_xrefs": assert_ok(fns["get_function_string_xrefs"](first["address"])),
            "get_xrefs_to_at": assert_ok(fns["get_xrefs_to_at"](first["address"])),
            "get_xrefs_from_at": assert_ok(fns["get_xrefs_from_at"](first["address"])),
            "get_strings": strings_result,
            "get_segments": assert_ok(fns["get_segments"]()),
            "get_segment_containing": assert_ok(fns["get_segment_containing"](first["address"])),
            "get_names": assert_ok(fns["get_names"]()),
            "demangle_name": assert_ok(fns["demangle_name"]("main")),
            "get_imports": assert_ok(fns["get_imports"]()),
            "get_entries": assert_ok(fns["get_entries"]()),
            "get_bytes_at": {"bytes": raw_bytes},
            "find_bytes": assert_ok(fns["find_bytes"](raw_bytes)),
            "get_disassembly_at": assert_ok(fns["get_disassembly_at"](first["address"])),
            "get_address_type": assert_ok(fns["get_address_type"](first["address"])),
            "read_pointer": assert_ok(fns["read_pointer"](first["address"])),
            "get_bookmarks": assert_ok(fns["get_bookmarks"]()),
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
            "get_function_data_xrefs": {"xrefs"},
            "get_function_string_xrefs": {"xrefs"},
            "get_xrefs_to_at": {"xrefs"},
            "get_xrefs_from_at": {"xrefs"},
            "get_strings": {"strings"},
            "get_segments": {"segments"},
            "get_segment_containing": {"name", "start", "end", "size", "permissions", "class", "bitness"},
            "get_names": {"names"},
            "demangle_name": {"demangled_name"},
            "get_imports": {"imports"},
            "get_entries": {"entries"},
            "get_bytes_at": {"bytes"},
            "find_bytes": {"addresses"},
            "get_disassembly_at": {"disassembly"},
            "get_address_type": {"address_type"},
            "read_pointer": {"pointer"},
            "get_bookmarks": {"bookmarks"},
        }

        for function_name, payload in payloads.items():
            assert_keys_exact(payload, expected_keys[function_name])

        if functions:
            assert_keys_exact(functions[0], {"address", "name", "size", "signature", "flags", "comment", "repeatable_comment"})

        bookmarks = payloads["get_bookmarks"]["bookmarks"]
        if bookmarks:
            assert_keys_exact(bookmarks[0], {"index", "address", "description"})

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

        if payloads["get_function_data_xrefs"]["xrefs"]:
            assert_keys_exact(
                payloads["get_function_data_xrefs"]["xrefs"][0],
                {"from_address", "to_address", "type"},
            )

        if payloads["get_function_string_xrefs"]["xrefs"]:
            assert_keys_exact(
                payloads["get_function_string_xrefs"]["xrefs"][0],
                {"from_address", "string_address", "string"},
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

    def test_factory_return_annotation_is_api_contract(self):
        hints = get_type_hints(create_api_from_database, include_extras=True)
        assert hints["return"] is api_types.ApiFunctions

    def test_has_all_functions(self, fns):
        for name in FUNCTION_NAMES:
            assert name in fns, f"missing function: {name}"
            assert callable(fns[name])

    def test_no_extra_functions(self, fns):
        assert set(fns.keys()) == set(FUNCTION_NAMES)


class TestExpectOkHelper:
    def test_returns_payload_for_success(self, fns):
        meta = fns["expect_ok"](fns["get_database_metadata"]())

        assert isinstance(meta, dict)
        assert "entry_point" in meta

    def test_returns_none_for_error_payload(self, fns):
        result = fns["expect_ok"](fns["get_function_at"](0xDEADDEAD))
        assert result is None


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

    def test_input_file_path_is_string(self, fns):
        info = assert_ok(fns["get_database_metadata"]())
        assert isinstance(info["input_file_path"], str)
        assert len(info["input_file_path"]) > 0

    def test_module_is_string(self, fns):
        info = assert_ok(fns["get_database_metadata"]())
        assert isinstance(info["module"], str)

    def test_architecture_is_string(self, fns):
        info = assert_ok(fns["get_database_metadata"]())
        assert isinstance(info["architecture"], str)
        assert len(info["architecture"]) > 0

    def test_bitness_is_32_or_64(self, fns):
        info = assert_ok(fns["get_database_metadata"]())
        assert isinstance(info["bitness"], int)
        assert info["bitness"] in (32, 64)
        assert info["bitness"] == 32

    def test_format_is_string(self, fns):
        info = assert_ok(fns["get_database_metadata"]())
        assert isinstance(info["format"], str)
        assert len(info["format"]) > 0

    def test_base_address_is_positive_int(self, fns):
        info = assert_ok(fns["get_database_metadata"]())
        assert isinstance(info["base_address"], int)
        assert info["base_address"] > 0

    def test_entry_point_is_int(self, fns):
        info = assert_ok(fns["get_database_metadata"]())
        assert isinstance(info["entry_point"], int)

    def test_minimum_ea_is_int(self, fns):
        info = assert_ok(fns["get_database_metadata"]())
        assert isinstance(info["minimum_ea"], int)

    def test_maximum_ea_is_int(self, fns):
        info = assert_ok(fns["get_database_metadata"]())
        assert isinstance(info["maximum_ea"], int)

    def test_minimum_ea_less_than_maximum_ea(self, fns):
        info = assert_ok(fns["get_database_metadata"]())
        assert info["minimum_ea"] < info["maximum_ea"]

    def test_input_file_size_is_positive_int(self, fns):
        info = assert_ok(fns["get_database_metadata"]())
        assert isinstance(info["input_file_size"], int)
        assert info["input_file_size"] > 0

    def test_input_file_md5_is_32_hex_chars(self, fns):
        info = assert_ok(fns["get_database_metadata"]())
        assert isinstance(info["input_file_md5"], str)
        assert len(info["input_file_md5"]) == 32
        assert all(c in "0123456789abcdef" for c in info["input_file_md5"].lower())

    def test_input_file_sha256_is_64_hex_chars(self, fns):
        info = assert_ok(fns["get_database_metadata"]())
        assert isinstance(info["input_file_sha256"], str)
        assert len(info["input_file_sha256"]) == 64
        assert all(c in "0123456789abcdef" for c in info["input_file_sha256"].lower())


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

    def test_callers_bad_address(self, fns):
        result = fns["get_function_callers"](0xDEADDEAD)
        assert "error" in result
        assert isinstance(result["error"], str)

    def test_callees_bad_address(self, fns):
        result = fns["get_function_callees"](0xDEADDEAD)
        assert "error" in result
        assert isinstance(result["error"], str)

    def test_callers_full_function_info(self, fns, first_func):
        result = assert_ok(fns["get_function_callers"](first_func["address"]))
        callers = result["callers"]
        for caller in callers:
            assert isinstance(caller["address"], int)
            assert isinstance(caller["name"], str)
            assert isinstance(caller["size"], int)
            assert isinstance(caller["signature"], str)
            assert isinstance(caller["flags"], dict)
            assert "noreturn" in caller["flags"]
            assert "library" in caller["flags"]
            assert "thunk" in caller["flags"]
            assert isinstance(caller["flags"]["noreturn"], bool)
            assert isinstance(caller["flags"]["library"], bool)
            assert isinstance(caller["flags"]["thunk"], bool)
            assert isinstance(caller["comment"], str)
            assert isinstance(caller["repeatable_comment"], str)

    def test_callees_full_function_info(self, fns, first_func):
        result = assert_ok(fns["get_function_callees"](first_func["address"]))
        callees = result["callees"]
        for callee in callees:
            assert isinstance(callee["address"], int)
            assert isinstance(callee["name"], str)
            assert isinstance(callee["size"], int)
            assert isinstance(callee["signature"], str)
            assert isinstance(callee["flags"], dict)
            assert "noreturn" in callee["flags"]
            assert "library" in callee["flags"]
            assert "thunk" in callee["flags"]
            assert isinstance(callee["flags"]["noreturn"], bool)
            assert isinstance(callee["flags"]["library"], bool)
            assert isinstance(callee["flags"]["thunk"], bool)
            assert isinstance(callee["comment"], str)
            assert isinstance(callee["repeatable_comment"], str)

    def test_callers_has_at_least_one_for_some_function(self, fns):
        functions = assert_ok(fns["get_functions"]())["functions"]
        found_callers = False
        for func in functions:
            result = assert_ok(fns["get_function_callers"](func["address"]))
            if len(result["callers"]) > 0:
                found_callers = True
                break
        assert found_callers, "No functions with callers found in test binary (32-bit PE malware sample should have call graph)"

    def test_callees_has_at_least_one_for_some_function(self, fns):
        functions = assert_ok(fns["get_functions"]())["functions"]
        found_callees = False
        for func in functions:
            result = assert_ok(fns["get_function_callees"](func["address"]))
            if len(result["callees"]) > 0:
                found_callees = True
                break
        assert found_callees, "No functions with callees found in test binary (32-bit PE malware sample should have call graph)"


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


class TestFunctionDataXrefs:
    def test_data_xrefs_shape(self, fns, first_func):
        xrefs = assert_ok(fns["get_function_data_xrefs"](first_func["address"]))["xrefs"]
        assert isinstance(xrefs, list)
        for x in xrefs:
            assert "from_address" in x
            assert "to_address" in x
            assert "type" in x
            assert isinstance(x["from_address"], int)
            assert isinstance(x["to_address"], int)
            assert isinstance(x["type"], str)

    def test_data_xrefs_bad_address(self, fns):
        result = fns["get_function_data_xrefs"](0xDEADDEAD)
        assert "error" in result
        assert isinstance(result["error"], str)

    def test_data_xrefs_not_function_start(self, fns, first_func):
        non_start = first_func["address"] + 1
        result = fns["get_function_data_xrefs"](non_start)
        assert "error" in result
        assert isinstance(result["error"], str)
        assert "not a function start" in result["error"]


class TestFunctionStringXrefs:
    def test_string_xrefs_shape(self, fns, first_func):
        xrefs = assert_ok(fns["get_function_string_xrefs"](first_func["address"]))["xrefs"]
        assert isinstance(xrefs, list)
        for x in xrefs:
            assert "from_address" in x
            assert "string_address" in x
            assert "string" in x
            assert isinstance(x["from_address"], int)
            assert isinstance(x["string_address"], int)
            assert isinstance(x["string"], str)

    def test_string_xrefs_bad_address(self, fns):
        result = fns["get_function_string_xrefs"](0xDEADDEAD)
        assert "error" in result
        assert isinstance(result["error"], str)

    def test_string_xrefs_not_function_start(self, fns, first_func):
        non_start = first_func["address"] + 1
        result = fns["get_function_string_xrefs"](non_start)
        assert "error" in result
        assert isinstance(result["error"], str)
        assert "not a function start" in result["error"]


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


class TestSegmentContaining:
    def test_get_segment_containing_valid_address(self, fns, first_func):
        seg = assert_ok(fns["get_segment_containing"](first_func["address"]))
        assert "name" in seg
        assert "start" in seg
        assert "end" in seg
        assert "size" in seg
        assert "permissions" in seg
        assert "class" in seg
        assert "bitness" in seg
        assert isinstance(seg["name"], str)
        assert isinstance(seg["start"], int)
        assert isinstance(seg["end"], int)
        assert isinstance(seg["size"], int)
        assert isinstance(seg["permissions"], int)
        assert isinstance(seg["class"], str)
        assert isinstance(seg["bitness"], int)
        assert seg["start"] <= first_func["address"] < seg["end"]

    def test_get_segment_containing_invalid_address(self, fns):
        result = fns["get_segment_containing"](0xDEADDEAD)
        assert "error" in result
        assert isinstance(result["error"], str)

    def test_segment_containing_matches_segment_list(self, fns, first_func):
        seg = assert_ok(fns["get_segment_containing"](first_func["address"]))
        all_segs = assert_ok(fns["get_segments"]())["segments"]
        matching_segs = [s for s in all_segs if s["start"] <= first_func["address"] < s["end"]]
        assert len(matching_segs) == 1
        assert seg["name"] == matching_segs[0]["name"]
        assert seg["start"] == matching_segs[0]["start"]
        assert seg["end"] == matching_segs[0]["end"]


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


class TestNoExceptionsContract:
    @pytest.mark.parametrize(
        ("function_name", "args"),
        [
            ("help", (None,)),
            ("get_function_at", ("abc",)),
            ("get_xrefs_to_at", ("abc",)),
            ("get_xrefs_from_at", ("abc",)),
            ("get_bytes_at", ("abc", "4")),
            ("find_bytes", (123,)),
            ("get_disassembly_at", ("abc",)),
            ("get_comment_at", ("abc",)),
            ("set_name_at", ("abc", 123)),
            ("set_type_at", ("abc", 123)),
            ("set_comment_at", ("abc", 123)),
            ("set_repeatable_comment_at", ("abc", 123)),
            ("set_local_variable_name", ("abc", 123, 456)),
            ("set_local_variable_type", ("abc", 123, 456)),
        ],
    )
    def test_invalid_inputs_return_payload_instead_of_raising(self, fns, function_name, args):
        try:
            result = fns[function_name](*args)
        except Exception as exc:
            pytest.fail(f"{function_name} raised unexpectedly: {type(exc).__name__}: {exc}")

        assert result is None or isinstance(result, dict)


class TestReadPointer:
    def test_read_pointer_valid_address(self, fns, first_func):
        result = assert_ok(fns["read_pointer"](first_func["address"]))
        assert "pointer" in result
        assert isinstance(result["pointer"], int)
        assert result["pointer"] >= 0

    def test_read_pointer_invalid_address(self, fns):
        result = fns["read_pointer"](0xDEADDEAD)
        assert "error" in result
        assert isinstance(result["error"], str)

    def test_read_pointer_consistency_with_get_bytes_at(self, fns, first_func):
        pointer_result = assert_ok(fns["read_pointer"](first_func["address"]))
        pointer_value = pointer_result["pointer"]

        bytes_result = assert_ok(fns["get_bytes_at"](first_func["address"], 4))
        raw_bytes = bytes_result["bytes"]

        assert len(raw_bytes) == 4
        expected_value = int.from_bytes(bytes(raw_bytes), byteorder="little", signed=False)

        assert pointer_value == expected_value


class TestMutatorConvention:
    def test_mutator_result_type_exists(self):
        assert hasattr(api_types, "MutatorResult")
        assert api_types.MutatorResult == None | api_types.ApiError

    def test_assert_mutator_success_accepts_none(self):
        assert_mutator_success(None)

    def test_assert_mutator_success_rejects_success_payload(self):
        with pytest.raises(pytest.fail.Exception, match="mutator returned non-None success value"):
            assert_mutator_success({"result": "success"})

    def test_assert_mutator_success_rejects_error(self):
        with pytest.raises(pytest.fail.Exception, match="expected mutator success"):
            assert_mutator_success({"error": "failed"})

    def test_assert_mutator_success_rejects_other_values(self):
        with pytest.raises(pytest.fail.Exception, match="mutator returned unexpected value"):
            assert_mutator_success(True)


class TestDatabaseMutators:
    def test_set_comment_at_success(self, fns, first_func):
        address = first_func["address"]
        test_comment = "Test comment from API integration test"

        original_comment_result = fns["get_comment_at"](address)
        original_comment = original_comment_result.get("comment") if "error" not in original_comment_result else None

        result = fns["set_comment_at"](address, test_comment)
        assert_mutator_success(result)

        verify_result = fns["get_comment_at"](address)
        assert_ok(verify_result)
        assert verify_result["comment"] == test_comment

        if original_comment:
            fns["set_comment_at"](address, original_comment)
        else:
            fns["set_comment_at"](address, "")

    def test_set_comment_at_bad_address(self, fns):
        result = fns["set_comment_at"](0xDEADDEAD, "should fail")
        assert "error" in result
        assert isinstance(result["error"], str)

    def test_set_repeatable_comment_at_success(self, fns, first_func):
        address = first_func["address"]
        test_comment = "Test repeatable comment from API"

        original_func = assert_ok(fns["get_function_at"](address))
        original_repeatable = original_func["repeatable_comment"]

        result = fns["set_repeatable_comment_at"](address, test_comment)
        assert_mutator_success(result)

        verify_func = assert_ok(fns["get_function_at"](address))
        assert verify_func["repeatable_comment"] == test_comment

        fns["set_repeatable_comment_at"](address, original_repeatable)

    def test_set_repeatable_comment_at_bad_address(self, fns):
        result = fns["set_repeatable_comment_at"](0xDEADDEAD, "should fail")
        assert "error" in result
        assert isinstance(result["error"], str)

    def test_set_name_at_success(self, fns, first_func):
        address = first_func["address"]
        test_name = "test_renamed_function"

        original_name_result = fns["get_name_at"](address)
        original_name = original_name_result.get("name") if "error" not in original_name_result else first_func["name"]

        result = fns["set_name_at"](address, test_name)
        assert_mutator_success(result)

        verify_result = fns["get_name_at"](address)
        assert_ok(verify_result)
        assert verify_result["name"] == test_name

        restore_result = fns["set_name_at"](address, original_name)
        assert_mutator_success(restore_result)

        final_result = fns["get_name_at"](address)
        assert_ok(final_result)
        assert final_result["name"] == original_name

    def test_set_name_at_bad_address(self, fns):
        result = fns["set_name_at"](0xDEADDEAD, "should_fail")
        assert "error" in result
        assert isinstance(result["error"], str)

    def test_set_type_at_success(self, fns, first_func):
        address = first_func["address"]
        test_type = "int __cdecl(void)"

        original_func = assert_ok(fns["get_function_at"](address))
        original_signature = original_func["signature"]

        result = fns["set_type_at"](address, test_type)
        assert_mutator_success(result)

        verify_func = assert_ok(fns["get_function_at"](address))
        assert verify_func["signature"] != original_signature
        assert "int" in verify_func["signature"]

        if original_signature:
            restore_result = fns["set_type_at"](address, original_signature)
            assert_mutator_success(restore_result)

            final_func = assert_ok(fns["get_function_at"](address))
            assert final_func["signature"] == original_signature
        else:
            result2 = fns["set_type_at"](address, "void __cdecl(void)")
            assert_mutator_success(result2)

            verify_func2 = assert_ok(fns["get_function_at"](address))
            assert "void" in verify_func2["signature"]

    def test_set_type_at_bad_address(self, fns):
        result = fns["set_type_at"](0xDEADDEAD, "int (void)")
        assert "error" in result
        assert isinstance(result["error"], str)

    def test_set_type_at_invalid_type_string(self, fns, first_func):
        result = fns["set_type_at"](first_func["address"], "not a valid type")
        assert "error" in result
        assert isinstance(result["error"], str)


class TestBookmarks:
    def test_get_bookmarks_returns_list(self, fns):
        result = assert_ok(fns["get_bookmarks"]())
        assert "bookmarks" in result
        assert isinstance(result["bookmarks"], list)

    def test_bookmark_shape(self, fns):
        bookmarks = assert_ok(fns["get_bookmarks"]())["bookmarks"]
        for bm in bookmarks:
            assert "index" in bm
            assert "address" in bm
            assert "description" in bm
            assert isinstance(bm["index"], int)
            assert isinstance(bm["address"], int)
            assert isinstance(bm["description"], str)

    def test_add_and_delete_bookmark(self, fns, first_func):
        initial_bookmarks = assert_ok(fns["get_bookmarks"]())["bookmarks"]
        initial_count = len(initial_bookmarks)

        test_address = first_func["address"]
        test_description = "Test bookmark for API"

        assert_mutator_success(fns["add_bookmark"](test_address, test_description))

        after_add = assert_ok(fns["get_bookmarks"]())["bookmarks"]
        assert len(after_add) == initial_count + 1

        added_bookmark = None
        for bm in after_add:
            if bm["address"] == test_address and bm["description"] == test_description:
                added_bookmark = bm
                break

        assert added_bookmark is not None, "newly added bookmark not found"

        assert_mutator_success(fns["delete_bookmark"](added_bookmark["index"]))

        after_delete = assert_ok(fns["get_bookmarks"]())["bookmarks"]
        assert len(after_delete) == initial_count

        for bm in after_delete:
            assert not (bm["address"] == test_address and bm["description"] == test_description)

    def test_delete_nonexistent_bookmark_fails(self, fns):
        result = fns["delete_bookmark"](999)
        assert "error" in result
        assert isinstance(result["error"], str)

    def test_add_bookmark_at_same_address_with_different_descriptions(self, fns, first_func):
        test_address = first_func["address"]

        initial_bookmarks = assert_ok(fns["get_bookmarks"]())["bookmarks"]
        initial_count = len(initial_bookmarks)

        assert_mutator_success(fns["add_bookmark"](test_address, "First bookmark"))
        assert_mutator_success(fns["add_bookmark"](test_address, "Second bookmark"))

        after_add = assert_ok(fns["get_bookmarks"]())["bookmarks"]
        assert len(after_add) == initial_count + 2

        matching = [bm for bm in after_add if bm["address"] == test_address]
        assert len(matching) >= 2

        for _ in range(len(matching)):
            current = assert_ok(fns["get_bookmarks"]())["bookmarks"]
            to_delete = [bm for bm in current if bm["address"] == test_address]
            if to_delete:
                assert_mutator_success(fns["delete_bookmark"](to_delete[0]["index"]))

        final_bookmarks = assert_ok(fns["get_bookmarks"]())["bookmarks"]
        assert len(final_bookmarks) == initial_count


class TestLocalVariableMutators:
    def test_set_local_variable_name(self, fns, first_func):
        result = fns["decompile_function_at"](first_func["address"])
        if "error" in result:
            pytest.skip("decompiler not available")

        nonexistent_name = "this_variable_does_not_exist_xyz123"
        result = fns["set_local_variable_name"](first_func["address"], nonexistent_name, "new_name")
        assert "error" in result
        assert isinstance(result["error"], str)
        assert "not found" in result["error"].lower() or "no local variable" in result["error"].lower()

    def test_set_local_variable_type(self, fns, first_func):
        result = fns["decompile_function_at"](first_func["address"])
        if "error" in result:
            pytest.skip("decompiler not available")

        nonexistent_name = "this_variable_does_not_exist_xyz123"
        result = fns["set_local_variable_type"](first_func["address"], nonexistent_name, "int")
        assert "error" in result
        assert isinstance(result["error"], str)
        assert "not found" in result["error"].lower() or "no local variable" in result["error"].lower()

    def test_set_local_variable_name_bad_address(self, fns):
        result = fns["set_local_variable_name"](0xDEADDEAD, "var1", "var2")
        assert "error" in result
        assert isinstance(result["error"], str)

    def test_set_local_variable_type_bad_address(self, fns):
        result = fns["set_local_variable_type"](0xDEADDEAD, "var1", "int")
        assert "error" in result
        assert isinstance(result["error"], str)

    def test_set_local_variable_name_not_function_start(self, fns, first_func):
        non_start = first_func["address"] + 1
        result = fns["set_local_variable_name"](non_start, "var1", "var2")
        assert "error" in result
        assert isinstance(result["error"], str)
        assert "not a function start" in result["error"]

    def test_set_local_variable_type_not_function_start(self, fns, first_func):
        non_start = first_func["address"] + 1
        result = fns["set_local_variable_type"](non_start, "var1", "int")
        assert "error" in result
        assert isinstance(result["error"], str)
        assert "not a function start" in result["error"]


class TestReadAsciiStringAt:
    def test_simple_ascii(self):
        buf = b"Hello\x00rest"
        assert read_ascii_string_at(buf) == b"Hello"

    def test_long_string(self):
        buf = b"ABCDEFGHIJ\x00"
        assert read_ascii_string_at(buf) == b"ABCDEFGHIJ"

    def test_min_len_default_rejects_short(self):
        buf = b"Hi\x00"
        assert read_ascii_string_at(buf) is None

    def test_min_len_custom(self):
        buf = b"Hi\x00"
        assert read_ascii_string_at(buf, min_len=2) == b"Hi"

    def test_empty_buffer(self):
        assert read_ascii_string_at(b"") is None

    def test_non_printable_first_byte(self):
        assert read_ascii_string_at(b"\x01Hello") is None

    def test_tab_is_printable(self):
        buf = b"\tHello\x00"
        assert read_ascii_string_at(buf) == b"\tHello"

    def test_no_null_terminator(self):
        buf = b"Hello World!"
        assert read_ascii_string_at(buf) == b"Hello World!"

    def test_exactly_min_len(self):
        buf = b"ABCD\x00"
        assert read_ascii_string_at(buf) == b"ABCD"

    def test_below_min_len(self):
        buf = b"ABC\x00"
        assert read_ascii_string_at(buf) is None


class TestReadUtf16leStringAt:
    def test_simple_utf16le(self):
        buf = b"H\x00e\x00l\x00l\x00o\x00\x00\x00"
        assert read_utf16le_string_at(buf) == b"H\x00e\x00l\x00l\x00o\x00"

    def test_min_len_default_rejects_short(self):
        buf = b"H\x00i\x00\x00\x00"
        assert read_utf16le_string_at(buf) is None

    def test_min_len_custom(self):
        buf = b"H\x00i\x00\x00\x00"
        assert read_utf16le_string_at(buf, min_len=2) == b"H\x00i\x00"

    def test_empty_buffer(self):
        assert read_utf16le_string_at(b"") is None

    def test_single_byte_buffer(self):
        assert read_utf16le_string_at(b"H") is None

    def test_non_printable_first_char(self):
        assert read_utf16le_string_at(b"\x01\x00e\x00") is None

    def test_non_zero_high_byte(self):
        assert read_utf16le_string_at(b"H\x01e\x00") is None

    def test_no_null_terminator(self):
        buf = b"H\x00e\x00l\x00l\x00o\x00"
        assert read_utf16le_string_at(buf) == b"H\x00e\x00l\x00l\x00o\x00"

    def test_odd_length_buffer(self):
        buf = b"H\x00e\x00l\x00l\x00o\x00X"
        assert read_utf16le_string_at(buf) == b"H\x00e\x00l\x00l\x00o\x00"


class TestReadStringAt:
    def test_prefers_ascii_over_utf16le(self):
        buf = b"Hello\x00"
        result = read_string_at(buf)
        assert result == b"Hello"

    def test_falls_back_to_utf16le(self):
        buf = b"H\x00e\x00l\x00l\x00o\x00\x00\x00"
        result = read_string_at(buf)
        assert result == b"H\x00e\x00l\x00l\x00o\x00"

    def test_returns_none_for_garbage(self):
        buf = b"\x00\x01\x02\x03"
        assert read_string_at(buf) is None

    def test_empty_buffer(self):
        assert read_string_at(b"") is None

    def test_ascii_too_short_but_utf16le_long_enough(self):
        buf = b"H\x00e\x00l\x00l\x00\x00\x00"
        result = read_string_at(buf, min_len=4)
        assert result == b"H\x00e\x00l\x00l\x00"
