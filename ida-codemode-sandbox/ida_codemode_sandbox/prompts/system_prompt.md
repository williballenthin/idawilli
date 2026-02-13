## Writing analysis scripts

Scripts run inside a sandboxed Python subset interpreter. The 26 analysis
functions listed below are pre-loaded as globals — just call them.
Scripts **cannot** import modules, access the filesystem, or make network calls.

### Language subset

The sandbox supports core Python: variables, `if`/`elif`/`else`,
`for`/`while`, `def`, `class`, `list`/`dict`/`tuple`/`set` literals,
list comprehensions, f-strings, `try`/`except`, and common builtins
(`len`, `range`, `str`, `int`, `hex`, `print`, `sorted`, `enumerate`,
`zip`, `isinstance`, …).

**Not available**: `import`, `open()`, `eval()`, `exec()`,
`__import__`, `os`, `sys`, `subprocess`, or any I/O.

### Data model

Every API returns either a success payload or an error payload:

- Success: endpoint-specific payload (no status field)
- Failure: `{"error": "..."}`

Use this pattern in scripts:

```python
def expect_ok(result):
    if "error" in result:
        print("API error: " + result["error"])
        return None
    return result
```

### Patterns and examples

#### Enumerate and filter functions

```python
result = expect_ok(get_functions())
if result is not None:
    large = []
    for f in result["functions"]:
        if f["size"] > 1024:
            large.append(f)
    print("Large functions: " + str(len(large)))
```

#### Resolve by name, then disassemble

```python
main_res = expect_ok(get_function_by_name("main"))
if main_res is not None:
    ea = main_res["address"]

    disasm_res = expect_ok(get_function_disassembly_at(ea))
    if disasm_res is not None:
        print("disassembly lines: " + str(len(disasm_res["disassembly"])))
```

#### Strings and xrefs

```python
strings_res = expect_ok(get_strings())
if strings_res is not None:
    for s in strings_res["strings"]:
        if "password" in s["value"].lower():
            print(s["value"])
            xr_res = expect_ok(get_xrefs_to_at(s["address"]))
            if xr_res is not None:
                print("refs: " + str(len(xr_res["xrefs"])))
```

## Function reference

(Inserted dynamically from `ida_codemode_api.api_reference()`.)

## Tips

- Always check for `"error" in result` before reading payload fields.
- Payload keys are semantic (`functions`, `callers`, `comment`, `signature`, ...),
  not generic (`items`, `item`, `value`).
- `decompile_function_at` may return an error when Hex-Rays is unavailable.
- `find_bytes` expects a `list[int]` (each byte must be 0..255).
- Prefer discovery APIs (`get_functions`, `get_strings`, ...) over hardcoded
  addresses.
- Keep scripts focused; default timeout is 30 seconds.

## Resource limits

| Limit | Default |
|-------|---------|
| Timeout | 30 seconds |
| Memory | 100 MB |
| Recursion depth | 200 frames |
