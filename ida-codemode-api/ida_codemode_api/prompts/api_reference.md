## Function reference

Read functions return the success payload shown below or `{error: str}` on failure.
Mutation functions return `None` on success or `{error: str}` on failure.
Utility helper `expect_ok(result)` returns the original success payload or `None` for ApiError.
For likely-success reads, prefer `expect_ok(...)`; branch on `None` before field access.

| Function | Returns | Description |
|----------|---------|-------------|
| `help(api: str)` | `{documentation: str}` | Extensive documentation for a specific API callback. |
| `expect_ok(result: ExpectOkPayload)` | `ExpectOkPayload | None` | Return success payloads as-is and normalize ApiError to None. |
| `get_database_metadata()` | `{input_file_path: str, module: str, architecture: str, bitness: int, format: str, base_address: int, entry_point: int, minimum_ea: int, maximum_ea: int, input_file_size: int, input_file_md5: str, input_file_sha256: str}` | Database-wide metadata for the currently opened database. |
| `get_functions()` | `{functions: list[{address: int, name: str, size: int, signature: str, flags: {noreturn: bool, library: bool, thunk: bool}, comment: str, repeatable_comment: str}]}` | All discovered function descriptors. |
| `get_function_by_name(name: str)` | `{address: int, name: str, size: int, signature: str, flags: {noreturn: bool, library: bool, thunk: bool}, comment: str, repeatable_comment: str}` | Function descriptor resolved by exact symbol name. |
| `get_function_at(address: int)` | `{address: int, name: str, size: int, signature: str, flags: {noreturn: bool, library: bool, thunk: bool}, comment: str, repeatable_comment: str}` | Function descriptor for a function start address. |
| `get_function_disassembly_at(address: int)` | `{disassembly: list[str]}` | Linear-disassembly lines for the containing function. |
| `decompile_function_at(address: int)` | `{pseudocode: list[str]}` | Hex-Rays pseudocode lines for the containing function. |
| `get_function_callers(address: int)` | `{callers: list[{address: int, name: str, size: int, signature: str, flags: {noreturn: bool, library: bool, thunk: bool}, comment: str, repeatable_comment: str}]}` | Functions that call the containing function. |
| `get_function_callees(address: int)` | `{callees: list[{address: int, name: str, size: int, signature: str, flags: {noreturn: bool, library: bool, thunk: bool}, comment: str, repeatable_comment: str}]}` | Functions called by the containing function. |
| `get_function_data_xrefs(function_start: int)` | `{xrefs: list[{from_address: int, to_address: int, type: str}]}` | Data cross-references originating from all instructions in a function. |
| `get_function_string_xrefs(function_start: int)` | `{xrefs: list[{from_address: int, string_address: int, string: str}]}` | String cross-references originating from all instructions in a function. |
| `get_xrefs_to_at(address: int)` | `{xrefs: list[{from_address: int, type: str, is_call: bool, is_jump: bool}]}` | Cross-references that target an address. |
| `get_xrefs_from_at(address: int)` | `{xrefs: list[{to_address: int, type: str, is_call: bool, is_jump: bool}]}` | Cross-references that originate at an address. |
| `get_strings()` | `{strings: list[{address: int, length: int, type: str, value: str}]}` | All strings recognized by IDA analysis. |
| `get_string_at(address: int)` | `{string: str}` | ASCII or UTF-16LE string decoded at an address. |
| `get_segments()` | `{segments: list[{name: str, start: int, end: int, size: int, permissions: int, class: str, bitness: int}]}` | Memory-segment descriptors for the loaded database. |
| `get_segment_containing(address: int)` | `{name: str, start: int, end: int, size: int, permissions: int, class: str, bitness: int}` | Segment descriptor for the segment containing an address. |
| `get_names()` | `{names: list[{address: int, name: str}]}` | All named addresses known to IDA. |
| `get_name_at(address: int)` | `{name: str}` | Symbol name at an exact address. |
| `demangle_name(name: str)` | `{demangled_name: str}` | Demangled form of a mangled symbol string. |
| `get_imports()` | `{imports: list[{address: int, name: str, module: str, ordinal: int}]}` | Imported symbols referenced by the binary. |
| `get_entries()` | `{entries: list[{ordinal: int, address: int, name: str, forwarder: str | None}]}` | Entry points and exported entry records. |
| `get_bytes_at(address: int, size: int)` | `{bytes: list[int]}` | Raw byte values from a contiguous address range. |
| `find_bytes(pattern: list[int])` | `{addresses: list[int]}` | Addresses where an exact byte pattern occurs. |
| `get_disassembly_at(address: int)` | `{disassembly: str}` | Disassembly text for one instruction address. |
| `get_address_type(address: int)` | `{address_type: Literal['code', 'data', 'unknown', 'invalid']}` | Address classification as code, data, unknown, or invalid. |
| `get_comment_at(address: int)` | `{comment: str}` | Comment text attached to an exact address. |
| `read_pointer(address: int)` | `{pointer: int}` | Unsigned pointer-sized integer at an address. |
| `get_bookmarks()` | `{bookmarks: list[{index: int, address: int, description: str}]}` | All bookmarks defined in the database. |
| `add_bookmark(address: int, description: str)` | `None` | Add a bookmark at an address. |
| `delete_bookmark(index: int)` | `None` | Delete a bookmark by its index. |
| `set_name_at(address: int, name: str)` | `None` | Set the symbol name at an address. |
| `set_type_at(address: int, type: str)` | `None` | Set the type signature at an address. |
| `set_comment_at(address: int, comment: str)` | `None` | Set the comment at an address. |
| `set_repeatable_comment_at(address: int, comment: str)` | `None` | Set the repeatable comment at an address. |
| `set_local_variable_name(function_address: int, existing_name: str, new_name: str)` | `None` | Set the name of a local variable within a function. |
| `set_local_variable_type(function_address: int, existing_name: str, type: str)` | `None` | Set the type of a local variable within a function. |

<!--- (autogenerated file: do not edit) -->
