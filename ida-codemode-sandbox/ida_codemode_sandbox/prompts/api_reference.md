## Function reference

All functions return either the success payload shown below or `{error: str}`.
Callers should check for the presence of the `error` key to detect failures.

| Function | Returns | Description |
|----------|---------|-------------|
| `get_binary_info()` | `{path: str, module: str, architecture: str, bitness: int, format: str, base_address: int, entry_point: int, minimum_ea: int, maximum_ea: int, filesize: int, md5: str, sha256: str, crc32: int}` |  |
| `get_functions()` | `{functions: list[{address: int, name: str, size: int}]}` |  |
| `get_function_by_name(name)` | `{address: int, name: str, size: int}` |  |
| `get_function_at(address)` | `{address: int, name: str, size: int}` |  |
| `get_function_disassembly_at(address)` | `{disassembly: list[str]}` |  |
| `decompile_function_at(address)` | `{pseudocode: list[str]}` |  |
| `get_function_signature_at(address)` | `{signature: str}` |  |
| `get_callers_at(address)` | `{callers: list[{address: int, name: str}]}` |  |
| `get_callees_at(address)` | `{callees: list[{address: int, name: str}]}` |  |
| `get_basic_blocks_at(address)` | `{basic_blocks: list[{start: int, end: int, successors: list[int], predecessors: list[int]}]}` |  |
| `get_xrefs_to_at(address)` | `{xrefs: list[{from_address: int, type: str, is_call: bool, is_jump: bool}]}` |  |
| `get_xrefs_from_at(address)` | `{xrefs: list[{to_address: int, type: str, is_call: bool, is_jump: bool}]}` |  |
| `get_strings()` | `{strings: list[{address: int, length: int, type: str, value: str}]}` |  |
| `get_string_at(address)` | `{string: str}` |  |
| `get_segments()` | `{segments: list[{name: str, start: int, end: int, size: int, permissions: int, class: str, bitness: int}]}` |  |
| `get_names()` | `{names: list[{address: int, name: str}]}` |  |
| `get_name_at(address)` | `{name: str}` |  |
| `demangle_name(name)` | `{demangled_name: str}` |  |
| `get_imports()` | `{imports: list[{address: int, name: str, module: str, ordinal: int}]}` |  |
| `get_entries()` | `{entries: list[{ordinal: int, address: int, name: str, forwarder: str | None}]}` |  |
| `get_bytes_at(address, size)` | `{bytes: list[int]}` |  |
| `find_bytes(pattern)` | `{addresses: list[int]}` |  |
| `get_disassembly_at(address)` | `{disassembly: str}` |  |
| `get_instruction_at(address)` | `{address: int, size: int, mnemonic: str, disassembly: str, is_call: bool}` |  |
| `get_address_type(address)` | `{address_type: Literal['code', 'data', 'unknown', 'invalid']}` |  |
| `get_comment_at(address)` | `{comment: str}` |  |
