## Function reference

### Database metadata

| Function | Returns | Description |
|----------|---------|-------------|
| `get_binary_info()` | `dict` | path, module, architecture, bitness, format, base_address, entry_point, minimum_ea, maximum_ea, filesize, md5, sha256, crc32 |

### Functions

| Function | Returns | Description |
|----------|---------|-------------|
| `enumerate_functions()` | `list[dict]` | All functions: `{address, name, size}` |
| `get_function_by_name(name)` | `dict \| None` | Look up by exact name |
| `disassemble_function(address)` | `list[str]` | Disassembly lines |
| `decompile_function(address)` | `list[str]` | C pseudocode (needs Hex-Rays) |
| `get_function_signature(address)` | `str \| None` | C-style type signature |
| `get_callers(address)` | `list[dict]` | Functions that call this one: `{address, name}` |
| `get_callees(address)` | `list[dict]` | Functions this one calls: `{address, name}` |
| `get_basic_blocks(address)` | `list[dict]` | CFG: `{start, end, successors, predecessors}` |

### Cross-references

| Function | Returns | Description |
|----------|---------|-------------|
| `get_xrefs_to(address)` | `list[dict]` | Refs targeting address: `{from_address, type, is_call, is_jump}` |
| `get_xrefs_from(address)` | `list[dict]` | Refs originating at address: `{to_address, type, is_call, is_jump}` |

### Strings

| Function | Returns | Description |
|----------|---------|-------------|
| `enumerate_strings()` | `list[dict]` | All strings: `{address, length, type, value}` |
| `get_string_at(address)` | `str \| None` | Read null-terminated C string |

### Segments

| Function | Returns | Description |
|----------|---------|-------------|
| `enumerate_segments()` | `list[dict]` | All segments: `{name, start, end, size, permissions, class, bitness}` |

### Names / symbols

| Function | Returns | Description |
|----------|---------|-------------|
| `enumerate_names()` | `list[dict]` | All named addresses: `{address, name}` |
| `get_name_at(address)` | `str \| None` | Symbol name at address |
| `demangle_name(name)` | `str` | Demangle C++ name (pass-through if not mangled) |

### Imports and entries

| Function | Returns | Description |
|----------|---------|-------------|
| `enumerate_imports()` | `list[dict]` | All imports: `{address, name, module, ordinal}` |
| `enumerate_entries()` | `list[dict]` | All entry points: `{ordinal, address, name, forwarder}` |

### Bytes / memory

| Function | Returns | Description |
|----------|---------|-------------|
| `read_bytes(address, size)` | `list[int]` | Raw byte values (0-255) |
| `find_bytes(pattern)` | `list[int]` | Addresses matching byte pattern |
| `get_disassembly_at(address)` | `str \| None` | Single instruction disassembly |
| `get_instruction_at(address)` | `dict \| None` | `{address, size, mnemonic, disassembly, is_call}` |

### Address classification

| Function | Returns | Description |
|----------|---------|-------------|
| `is_code_at(address)` | `bool` | Address contains code |
| `is_data_at(address)` | `bool` | Address contains defined data |
| `is_valid_address(address)` | `bool` | Address is mapped |

### Comments

| Function | Returns | Description |
|----------|---------|-------------|
| `get_comment_at(address)` | `str \| None` | Analyst comment at address |

### Utilities

| Function | Returns | Description |
|----------|---------|-------------|
| `random_int(low, high)` | `int` | Random integer in `[low, high]` |
