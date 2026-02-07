# API Surface Comparison: ida-codemode-api vs ida-pro-mcp vs IDASQL

## Executive Summary

| | ida-codemode-api | ida-pro-mcp | IDASQL |
|---|---|---|---|
| **Author** | Willi Ballenthin | mrexodia | allthingsida |
| **Language** | Python | Python | C++17 |
| **Interface** | Pure functions (dict in/out) | MCP tools + resources | SQL virtual tables + scalar functions |
| **Total operations** | 28 functions | ~71 tools + 24 resources | ~23 tables + 50+ SQL functions + 18 views |
| **Read-only** | Yes (all) | No (has write/patch/rename) | No (has UPDATE/DELETE + write functions) |
| **Decompiler** | 1 function | 1 tool + export | 4 tables + 2 functions + 9 views |
| **Debugger** | None | 20 tools (extension) | None |
| **Write operations** | None | Rename, comment, patch, type edit | Rename, comment (via UPDATE + functions) |
| **Arbitrary code exec** | None (sandbox companion) | `py_eval` (unsafe) | None |
| **IDA requirement** | `ida-domain` (idalib) | IDA Pro 8.3+ (GUI plugin) | IDA SDK 9.0+ (GUI plugin or CLI) |

---

## Category-by-Category Comparison

### 1. Binary / Database Metadata

| Capability | ida-codemode-api | ida-pro-mcp | IDASQL |
|---|---|---|---|
| File path | `get_binary_info()["path"]` | `idb_metadata` resource | `db_info` WHERE key='input_file' |
| Architecture | `["architecture"]` | `idb_metadata` | `db_info` WHERE key='processor' |
| Bitness | `["bitness"]` | `idb_metadata` | `db_info` WHERE key='is_64bit' |
| File format | `["format"]` | `idb_metadata` | `db_info` WHERE key='filetype' |
| Base address | `["base_address"]` | `idb_metadata` | `db_info` WHERE key='min_ea' |
| Entry point | `["entry_point"]` | `idb_metadata` | `db_info` WHERE key='start_ea' |
| Min/Max EA | `["minimum_ea"]`, `["maximum_ea"]` | `idb_metadata` | `db_info` |
| File size | `["filesize"]` | `idb_metadata` | -- |
| MD5 | `["md5"]` | `idb_metadata` | -- |
| SHA256 | `["sha256"]` | `idb_metadata` | -- |
| CRC32 | `["crc32"]` | `idb_metadata` | -- |
| Analysis settings | -- | -- | `ida_info` table |

**Overlap**: All three cover the core metadata (arch, bitness, base, entry). ida-codemode-api and ida-pro-mcp both include hashes; IDASQL does not. IDASQL uniquely exposes IDA analysis settings.

### 2. Function Enumeration & Lookup

| Capability | ida-codemode-api | ida-pro-mcp | IDASQL |
|---|---|---|---|
| List all functions | `enumerate_functions()` | `list_funcs` | `SELECT * FROM funcs` |
| Lookup by name | `get_function_by_name(name)` | `lookup_funcs` | `SELECT * FROM funcs WHERE name='...'` |
| Lookup by address | -- | `lookup_funcs` | `SELECT * FROM funcs WHERE address=0x...` |
| Glob/regex filter | -- | `list_funcs` (glob+regex) | SQL LIKE / GLOB |
| Pagination | -- | `list_funcs` (offset+count) | SQL LIMIT/OFFSET |
| Function count | via `len(enumerate_functions())` | -- | `func_qty()` scalar |
| Function by index | -- | -- | `func_at_index(n)` scalar |
| Function flags | -- | -- | `funcs.flags` column |
| Return type info | -- | -- | `funcs.return_type`, `return_is_ptr`, etc. |
| Calling convention | -- | -- | `funcs.calling_conv` |
| Argument count | -- | -- | `funcs.arg_count` |

**Gap in ida-codemode-api**: No pagination, no filtering, no lookup by address, no function metadata beyond `{address, name, size}`. The `enumerate_functions()` call returns the entire list every time, which may be expensive for large binaries. ida-pro-mcp and IDASQL both support filtered/paginated access.

### 3. Disassembly

| Capability | ida-codemode-api | ida-pro-mcp | IDASQL |
|---|---|---|---|
| Disassemble function | `disassemble_function(addr)` → list[str] | `disasm` → structured lines | `SELECT * FROM instructions WHERE func_addr=X` |
| Single instruction | `get_disassembly_at(addr)` | -- | `disasm(addr)` scalar |
| Structured instruction | `get_instruction_at(addr)` | `disasm` (per-line fields) | `decode_insn(addr)` scalar, `instructions` table |
| Operand access | -- | disasm line fields | `operand(addr, n)`, `operand_type(addr, n)`, `operand_value(addr, n)` |
| Mnemonic only | -- | -- | `mnemonic(addr)` scalar |
| Pagination | -- | `disasm` (offset + max_instructions) | SQL LIMIT/OFFSET |
| Stack frame in output | -- | `disasm` includes stack_frame | `stack_frame` (via types_members on frame struct) |
| All heads (items) | -- | -- | `heads` table |

**Gap in ida-codemode-api**: Returns flat text lines rather than structured data. No individual operand access. No pagination for large functions.

**IDASQL advantage**: SQL composability means you can `JOIN instructions` with `funcs`, `xrefs`, etc. in a single query. Dedicated `heads` table exposes every defined item.

### 4. Decompilation

| Capability | ida-codemode-api | ida-pro-mcp | IDASQL |
|---|---|---|---|
| Decompile function | `decompile_function(addr)` → list[str] | `decompile` → pseudocode text | `decompile(addr)` scalar, `pseudocode` table |
| Per-line address mapping | -- | -- | `pseudocode.ea` column |
| Local variables | -- | -- | `ctree_lvars` table (name, type, storage, offsets) |
| Rename local var | -- | `rename` (batch, locals) | `UPDATE ctree_lvars SET name='...'` |
| Retype local var | -- | `set_type` (local) | `UPDATE ctree_lvars SET type='...'` |
| AST / ctree access | -- | -- | `ctree` table (28 columns per node) |
| Call argument analysis | -- | -- | `ctree_call_args` table |
| Loop detection | -- | -- | `ctree_v_loops` view, `disasm_loops` table |
| Comparison analysis | -- | -- | `ctree_v_comparisons` view |
| Calls inside loops | -- | -- | `ctree_v_calls_in_loops` view |

**Gap in ida-codemode-api**: Returns flat pseudocode text. No local variable access, no renaming, no AST inspection.

**IDASQL advantage**: Deep ctree/AST access is unique. No other project exposes Hex-Rays intermediate representation as queryable data. The analytical views (loops, comparisons, assignments, call chains) are powerful for automated analysis.

### 5. Cross-References

| Capability | ida-codemode-api | ida-pro-mcp | IDASQL |
|---|---|---|---|
| Xrefs to address | `get_xrefs_to(addr)` | `xrefs_to` | `SELECT * FROM xrefs WHERE to_ea=X` |
| Xrefs from address | `get_xrefs_from(addr)` | `xrefs_from` resource | `SELECT * FROM xrefs WHERE from_ea=X` |
| Xref type classification | `type`, `is_call`, `is_jump` | `type` (code/data) | `type`, `is_code` |
| Xrefs to struct field | -- | `xrefs_to_field` | -- |
| Callers (function-level) | `get_callers(addr)` | (via xrefs_to) | `callers` view |
| Callees (function-level) | `get_callees(addr)` | `callees` tool | `callees` view |
| Batch xrefs | -- | `xrefs_to` (multiple addrs) | SQL IN clause |
| Limit | -- | `xrefs_to` (limit param) | SQL LIMIT |

**Overlap**: All three cover the core xref operations. ida-pro-mcp uniquely has struct-field xrefs. IDASQL has pre-built `callers`/`callees` views.

### 6. Strings

| Capability | ida-codemode-api | ida-pro-mcp | IDASQL |
|---|---|---|---|
| List all strings | `enumerate_strings()` | (via `find_regex`) | `SELECT * FROM strings` |
| String at address | `get_string_at(addr)` | `get_string` | strings table + content column |
| Regex search | -- | `find_regex` | SQL LIKE / GLOB on content |
| String type metadata | `type` field | -- | `type`, `type_name`, `width`, `layout`, `encoding` |
| String refs to functions | -- | -- | `string_refs` view (JOIN xrefs+strings+funcs) |
| Rebuild string list | -- | -- | `rebuild_strings()` function |

**Gap in ida-codemode-api**: No regex search over strings. IDASQL has by far the richest string metadata.

### 7. Segments

| Capability | ida-codemode-api | ida-pro-mcp | IDASQL |
|---|---|---|---|
| List segments | `enumerate_segments()` | `idb_segments` resource | `SELECT * FROM segments` |
| Fields | name, start, end, size, permissions, class, bitness | name, start, end, size, rwx | start_ea, end_ea, name, class, perm |
| Segment at address | -- | -- | `segment_at(addr)` scalar |

**Overlap**: Near-complete overlap. ida-codemode-api has the most detailed per-segment metadata (bitness per segment).

### 8. Names / Symbols

| Capability | ida-codemode-api | ida-pro-mcp | IDASQL |
|---|---|---|---|
| All names | `enumerate_names()` | -- | `SELECT * FROM names` |
| Name at address | `get_name_at(addr)` | -- | `name_at(addr)` scalar |
| Demangle | `demangle_name(name)` | -- | -- |
| Set name | -- | `rename` (batch) | `set_name(addr, name)`, `UPDATE names SET name=...` |
| Public/weak flags | -- | -- | `names.is_public`, `names.is_weak` |
| List globals | -- | `list_globals` (non-function names) | (via SQL filter on names) |

**Gap in ida-codemode-api**: Read-only. Cannot rename anything. ida-pro-mcp has the most sophisticated renaming (functions, globals, locals, stack vars in one batch call).

### 9. Imports & Exports / Entry Points

| Capability | ida-codemode-api | ida-pro-mcp | IDASQL |
|---|---|---|---|
| List imports | `enumerate_imports()` | `imports` tool | `SELECT * FROM imports` |
| Import fields | address, name, module, ordinal | addr, imported_name, module | address, name, ordinal, module, module_idx |
| Lookup import by name | -- | `import/{name}` resource | SQL WHERE |
| List entries/exports | `enumerate_entries()` | `idb_entrypoints` resource | `SELECT * FROM entries` |
| Entry fields | ordinal, address, name, forwarder | ordinal, address, name | ordinal, address, name |
| Lookup export by name | -- | `export/{name}` resource | SQL WHERE |

**Overlap**: Near-complete overlap. ida-pro-mcp has dedicated lookup-by-name resources.

### 10. Basic Blocks / CFG

| Capability | ida-codemode-api | ida-pro-mcp | IDASQL |
|---|---|---|---|
| Get basic blocks | `get_basic_blocks(addr)` | `basic_blocks` | `SELECT * FROM blocks WHERE func_ea=X` |
| Successors/predecessors | Yes (lists of start addrs) | Yes | -- (only start/end/size) |
| CFG as DOT graph | -- | -- | `gen_cfg_dot(addr)` scalar |
| Pagination | -- | offset + max_blocks | SQL LIMIT/OFFSET |

**Gap in IDASQL blocks table**: No successor/predecessor columns (must derive via xrefs). But it uniquely can generate DOT graph output.

### 11. Memory / Bytes

| Capability | ida-codemode-api | ida-pro-mcp | IDASQL |
|---|---|---|---|
| Read bytes | `read_bytes(addr, size)` → list[int] | `get_bytes` → hex string | `bytes(addr, count)` scalar → hex string |
| Raw bytes | -- | -- | `bytes_raw(addr, count)` → BLOB |
| Read int (typed) | -- | `get_int` (i8/u32le/etc.) | -- |
| Read global value | -- | `get_global_value` | -- |
| Pattern search | `find_bytes(pattern)` | `find_bytes` (with wildcards) | `search_bytes(pattern)` (with wildcards + alternatives) |
| Write/patch bytes | -- | `patch` | -- |
| Write int | -- | `put_int` | -- |
| Patch assembly | -- | `patch_asm` | -- |

**Gap in ida-codemode-api**: No typed integer reads, no wildcard patterns, no write operations. ida-pro-mcp has the most complete memory manipulation. IDASQL's `search_bytes` supports the most flexible pattern syntax (alternatives via parentheses).

### 12. Comments

| Capability | ida-codemode-api | ida-pro-mcp | IDASQL |
|---|---|---|---|
| Read comment | `get_comment_at(addr)` | -- | `comment_at(addr)`, `comments` table |
| Set comment | -- | `set_comments` (disasm + decompiler) | `set_comment(addr, text)`, `UPDATE comments` |
| Repeatable comments | -- | -- | `comments.rpt_comment` column |
| Function comments | -- | `set_comments` (function-level) | -- |

**Gap in ida-codemode-api**: Read-only. Cannot set comments. IDASQL distinguishes regular vs repeatable comments.

### 13. Type System

| Capability | ida-codemode-api | ida-pro-mcp | IDASQL |
|---|---|---|---|
| Function signature | `get_function_signature(addr)` | `export_funcs` (prototypes format) | via `funcs.return_type`, `types_func_args` table |
| Declare C type | -- | `declare_type` | -- |
| Apply type to function | -- | `set_type` (function) | -- |
| Apply type to global | -- | `set_type` (global) | -- |
| Apply type to local var | -- | `set_type` (local) | -- |
| List all types | -- | `types` resource | `SELECT * FROM types` |
| List structs | -- | `structs` resource, `search_structs` | `types_v_structs` view |
| Struct definition | -- | `struct/{name}` resource | `types_members` table |
| Read struct from memory | -- | `read_struct` | -- |
| Infer types | -- | `infer_types` | -- |
| Enum values | -- | -- | `types_enum_values` table |
| Type composition (JOINs) | -- | -- | SQL JOINs across type tables |

**Gap in ida-codemode-api**: Only exposes function signatures as strings. No type system access at all.

**IDASQL advantage**: Full relational access to types, members, enum values, and function args. Can compose queries like "find all structs containing a field of type X."

**ida-pro-mcp advantage**: Write operations (declare, apply, infer).

### 14. Stack Frames

| Capability | ida-codemode-api | ida-pro-mcp | IDASQL |
|---|---|---|---|
| Read stack frame | -- | `stack_frame` | (via type system tables) |
| Declare stack var | -- | `declare_stack` | -- |
| Delete stack var | -- | `delete_stack` | -- |
| Rename stack var | -- | `rename` (stack category) | -- |
| Retype stack var | -- | `set_type` (stack) | -- |

**Gap in ida-codemode-api**: No stack frame operations at all. ida-pro-mcp has comprehensive stack manipulation.

### 15. Address Classification

| Capability | ida-codemode-api | ida-pro-mcp | IDASQL |
|---|---|---|---|
| Is code | `is_code_at(addr)` | -- | `is_code(addr)` scalar |
| Is data | `is_data_at(addr)` | -- | `is_data(addr)` scalar |
| Is valid address | `is_valid_address(addr)` | -- | -- |
| Item type | -- | -- | `item_type(addr)` (code/data/string/etc.) |
| Item size | -- | -- | `item_size(addr)` |
| Raw flags | -- | -- | `flags_at(addr)` |

**Overlap**: ida-codemode-api and IDASQL both cover code/data classification. IDASQL goes deeper with `item_type` and raw flags.

### 16. Debugger

| Capability | ida-codemode-api | ida-pro-mcp | IDASQL |
|---|---|---|---|
| Start/stop process | -- | `dbg_start`, `dbg_exit` | -- |
| Step into/over | -- | `dbg_step_into`, `dbg_step_over` | -- |
| Continue/run to | -- | `dbg_continue`, `dbg_run_to` | -- |
| Breakpoints | -- | `dbg_bps`, `dbg_add_bp`, `dbg_delete_bp`, `dbg_toggle_bp` | -- |
| Registers | -- | `dbg_regs`, `dbg_gpregs`, `dbg_regs_named` | -- |
| Stack trace | -- | `dbg_stacktrace` | -- |
| Live memory r/w | -- | `dbg_read`, `dbg_write` | -- |

**ida-pro-mcp exclusive**: Full debugger integration is unique to ida-pro-mcp. Neither ida-codemode-api nor IDASQL offers any runtime debugging.

### 17. Call Graph & Higher-Level Analysis

| Capability | ida-codemode-api | ida-pro-mcp | IDASQL |
|---|---|---|---|
| Call graph traversal | -- | `callgraph` (depth-limited BFS) | `disasm_v_call_chains` view (recursive CTE, depth 10) |
| Leaf function detection | -- | -- | `disasm_v_leaf_funcs`, `ctree_v_leaf_funcs` views |
| Loop detection | -- | -- | `disasm_loops` table, `ctree_v_loops` view |
| Calls in loops | -- | -- | `disasm_v_calls_in_loops`, `ctree_v_calls_in_loops` views |
| Export to C header | -- | `export_funcs` (c_header format) | -- |
| Export to JSON | -- | `export_funcs` (json format) | -- |
| Generate ASM file | -- | -- | `gen_asm_file()` |
| Generate HTML | -- | -- | `gen_html_file()` |
| Generate MAP file | -- | -- | `gen_map_file()` |

**IDASQL exclusive**: Deep analytical views (loops, call chains, leaf functions) are pre-built. These are the kinds of queries reverse engineers run frequently.

### 18. Bookmarks, Problems, Fixups, Hidden Ranges

| Capability | ida-codemode-api | ida-pro-mcp | IDASQL |
|---|---|---|---|
| Bookmarks | -- | -- | `bookmarks` table (r/w) |
| Analysis problems | -- | -- | `problems` table |
| Fixups/relocations | -- | -- | `fixups` table |
| Hidden ranges | -- | -- | `hidden_ranges` table |
| Function chunks | -- | -- | `fchunks` table |
| FLIRT signatures | -- | -- | `signatures` table |
| Address mappings | -- | -- | `mappings` table |

**IDASQL exclusive**: These "deep IDB" entities are not exposed by either of the other two projects.

### 19. UI / Cursor State

| Capability | ida-codemode-api | ida-pro-mcp | IDASQL |
|---|---|---|---|
| Cursor position | -- | `cursor` resource | -- |
| Selection range | -- | `selection` resource | -- |

**ida-pro-mcp exclusive**: Because it runs as a GUI plugin, it can access the current cursor and selection.

### 20. Arbitrary Execution

| Capability | ida-codemode-api | ida-pro-mcp | IDASQL |
|---|---|---|---|
| Run Python in IDA | -- (sandbox companion) | `py_eval` (unsafe) | -- |
| Sandboxed execution | ida-codemode-sandbox | -- | -- |
| Natural language SQL | -- | -- | `idasql_agent` MCP tool |

**Trade-off**: ida-pro-mcp offers raw `py_eval` (unsafe, full IDA access). ida-codemode-api's companion sandbox is more secure (no filesystem, no imports, resource-limited). IDASQL has an AI agent that converts natural language to SQL.

---

## What ida-codemode-api Has That Others Don't

| Feature | Notes |
|---|---|
| `demangle_name()` | Dedicated demangling. ida-pro-mcp and IDASQL don't expose this directly. |
| `random_int()` | Utility for sandboxed scripts. Neither other project needs this. |
| `is_valid_address()` | Explicit address validation. |
| Pure-function contract | Every function is stateless, JSON-safe, exception-safe. This makes it uniquely suitable for sandboxed/untrusted code execution. |

---

## Gaps in ida-codemode-api Relative to Both Others

### High Priority (requested by users in ida-pro-mcp issues)

| Missing Capability | ida-pro-mcp | IDASQL | Frequently Requested? |
|---|---|---|---|
| **Rename functions/globals** | `rename` batch tool | `set_name()`, UPDATE | Yes -- #61 (stack vars), many users want LLMs to annotate as they analyze |
| **Set comments** | `set_comments` | `set_comment()`, UPDATE | Yes -- core workflow: analyze → annotate |
| **Set/apply types** | `declare_type`, `set_type` | -- | Yes -- users want LLMs to apply recovered types |
| **Pagination for large results** | Most tools support offset+count | SQL LIMIT/OFFSET | Yes -- #35 (disasm output), large binaries choke without pagination |
| **Regex/glob string search** | `find_regex` | SQL LIKE/GLOB on strings | Yes -- #67 (search text function) |
| **Byte pattern search with wildcards** | `find_bytes` with `??` | `search_bytes` with `??` and alternatives | Yes -- core RE workflow |
| **List globals (non-function symbols)** | `list_globals` | filter names table | Users want to browse data symbols separately |

### Medium Priority

| Missing Capability | ida-pro-mcp | IDASQL | Notes |
|---|---|---|---|
| Structured disassembly output | Per-field (mnemonic, operands, comments) | `instructions` table columns | ida-codemode-api returns flat text |
| Local variable access | `rename`, `set_type` for locals | `ctree_lvars` table | Important for decompiler-assisted analysis |
| Stack frame introspection | `stack_frame`, `declare_stack` | via type tables | Function internals |
| Type system browsing | `types`, `structs` resources | `types`, `types_members` tables | Understanding data structures |
| Call graph traversal | `callgraph` tool | `disasm_v_call_chains` view | Tracing execution paths |
| Import/export lookup by name | Resources: `import/{name}`, `export/{name}` | SQL WHERE | Convenient for targeted queries |
| Function lookup by address | `lookup_funcs` auto-detects | SQL WHERE | ida-codemode-api requires exact name |

### Lower Priority (nice to have)

| Missing Capability | ida-pro-mcp | IDASQL | Notes |
|---|---|---|---|
| Cursor/selection state | Resources | -- | Only meaningful with GUI |
| Debugger | 20 tools | -- | Runtime analysis; different use case |
| Memory patching | `patch`, `put_int`, `patch_asm` | -- | Write operations |
| Bookmarks | -- | `bookmarks` table | Niche but useful |
| Analysis problems | -- | `problems` table | Meta-analysis |
| File generation (ASM, MAP, HTML) | -- | `gen_*` functions | Export workflows |
| Struct field xrefs | `xrefs_to_field` | -- | Advanced type-aware xrefs |

---

## Community Demand Signals (from ida-pro-mcp Issues)

The ida-pro-mcp issue tracker (250+ issues) reveals what users want from an IDA-to-LLM bridge:

### Most Requested Categories

1. **Client integration** (~30% of issues): Users want to connect from Claude Desktop, VS Code, Cursor, Windsurf, Gemini CLI, Codex CLI, etc. This suggests the transport/protocol layer matters as much as the API surface.

2. **Memory operations** (#54, #55 -- now implemented): Reading typed values (u8, u32, strings) from addresses. ida-codemode-api has `read_bytes` but not typed reads.

3. **Rename and annotate** (#61 and many implicit): LLMs analyzing code want to write back their findings -- rename variables, set comments, apply types. ida-codemode-api is entirely read-only.

4. **Better disassembly output** (#35, #34, #169): Users want structured disassembly (tokens, not strings) and simplified/filtered decompilation output.

5. **Search capabilities** (#67): Text/regex search across the entire database. ida-codemode-api has no search beyond `find_bytes`.

6. **Multi-instance support** (#53, #107): Analyzing multiple binaries simultaneously. Relevant for ida-codemode-api if it adds a server mode.

7. **Debugging** (#189 tracing): Some users want dynamic analysis integrated with LLM workflows.

IDASQL has zero issues (new project), so there's no community signal there yet.

---

## Design Philosophy Differences

### ida-codemode-api: Minimal, Safe, Sandboxable
- **28 read-only functions** -- the smallest surface area
- Every function is pure: JSON in, JSON out, no side effects
- Designed for untrusted code execution (companion sandbox)
- Trade-off: cannot annotate, rename, or modify the database

### ida-pro-mcp: Comprehensive, Interactive, LLM-Native
- **71+ tools** spanning read, write, debug, and code execution
- Batch-first design (most tools accept lists)
- Pagination and output truncation for LLM context windows
- Trade-off: large attack surface (`py_eval`, patching, debugging)

### IDASQL: Composable, Analytical, Query-Native
- **SQL as the API** -- every entity is a table you can JOIN, filter, aggregate
- Pre-built analytical views (loops, call chains, leaf functions)
- Deep ctree/AST access unique among all three
- Trade-off: SQL is verbose for simple operations; limited write support

---

## Recommendations for ida-codemode-api

Based on this analysis, the highest-value additions would be:

1. **Write-back operations** (rename, comment, set type) -- These are the #1 gap. Every user of ida-pro-mcp's rename/comment tools demonstrates demand. Without write-back, an LLM can analyze but cannot record its findings, which halves the value proposition.

2. **Pagination** -- `enumerate_functions()` returning 50,000 functions at once is impractical. Adding `offset`/`limit` parameters (or a cursor-based approach) to enumeration functions would make the API usable on real-world binaries.

3. **Filtered string search** -- A `search_strings(pattern)` function with regex/glob support. This is how most reverse engineering sessions begin: search for interesting strings, follow xrefs.

4. **Wildcard byte search** -- Upgrade `find_bytes` to support `??` wildcards. This is standard in RE tooling and both competitors support it.

5. **Structured disassembly** -- Return `{mnemonic, operands, address, size}` dicts instead of (or in addition to) flat text strings. This enables programmatic analysis of instruction patterns.

6. **Type system read access** -- At minimum, list structs/enums and their members. Both competitors expose this and it's essential for understanding data structures.

7. **Call graph traversal** -- A `get_call_graph(addr, depth)` function. Both competitors offer this; it's core to understanding program structure.
