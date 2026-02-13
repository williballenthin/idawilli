## Function reference

| Function | Returns | Description |
|----------|---------|-------------|
| `get_binary_info()` | `{path, module, architecture, bitness, format, base_address, entry_point, minimum_ea, maximum_ea, filesize, md5, sha256, crc32}` | Return global metadata about the analyzed binary. |
| `get_functions()` | `list[{address, name, size}]` | Return every discovered function descriptor. |
| `get_function_by_name(name)` | `{address, name, size} | None` | Look up a function by exact symbolic name. |
| `get_function_at(address)` | `{address, name, size} | None` | Look up the function that starts at the given address. |
| `get_function_disassembly_at(address)` | `list[str]` | Return disassembly lines for the function at address. |
| `decompile_function_at(address)` | `list[str]` | Return Hex-Rays pseudocode lines for the function at address. |
| `get_function_signature_at(address)` | `str | None` | Return the C-like function signature at address. |
| `get_callers_at(address)` | `list[{address, name}]` | Return callers of the function at address. |
| `get_callees_at(address)` | `list[{address, name}]` | Return callees of the function at address. |
| `get_basic_blocks_at(address)` | `list[{start, end, successors, predecessors}]` | Return CFG basic blocks for the function at address. |
| `get_xrefs_to_at(address)` | `list[{from_address, type, is_call, is_jump}]` | Return all cross-references that target address. |
| `get_xrefs_from_at(address)` | `list[{to_address, type, is_call, is_jump}]` | Return all cross-references that originate at address. |
| `get_strings()` | `list[{address, length, type, value}]` | Return every string recognized by IDA. |
| `get_string_at(address)` | `str | None` | Return a null-terminated C string at address. |
| `get_segments()` | `list[{name, start, end, size, permissions, class, bitness}]` | Return all memory segment descriptors. |
| `get_names()` | `list[{address, name}]` | Return all named addresses. |
| `get_name_at(address)` | `str | None` | Return the symbol name at address. |
| `demangle_name(name)` | `str` | Demangle a C++ symbol name. |
| `get_imports()` | `list[{address, name, module, ordinal}]` | Return imported symbols. |
| `get_entries()` | `list[{ordinal, address, name, forwarder}]` | Return entry points and exported symbols. |
| `get_bytes_at(address, size)` | `list[int]` | Return raw bytes at address. |
| `find_bytes(pattern)` | `list[int]` | Return addresses matching a byte pattern. |
| `get_disassembly_at(address)` | `str | None` | Return disassembly text for one instruction. |
| `get_instruction_at(address)` | `{address, size, mnemonic, disassembly, is_call} | None` | Return structured instruction data at address. |
| `get_address_type(address)` | `AddressType` | Classify address as code, data, unknown, or invalid. |
| `get_comment_at(address)` | `str | None` | Return the comment attached to address. |
