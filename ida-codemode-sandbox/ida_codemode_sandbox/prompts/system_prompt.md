## Writing analysis scripts

Scripts run inside a sandboxed Python subset interpreter.
Many IDA analysis and annotation routines are pre-loaded as globals.
Scripts **cannot** import modules, access the filesystem, or make network calls.

### Language subset

The sandbox supports core Python: variables, `if`/`elif`/`else`,
`for`/`while`, `def`, `class`, `list`/`dict`/`tuple`/`set` literals,
list comprehensions, f-strings, `try`/`except`, and common builtins
(`len`, `range`, `str`, `int`, `hex`, `print`, `sorted`, `enumerate`,
`zip`, `isinstance`, …).

**Not available**: `import`, `open()`, `eval()`, `exec()`,
`__import__`, `os`, `sys`, `subprocess`, or any I/O.

### API call pattern

Each callback returns either:

- a success payload
- `{"error": "..."}`

Use `is_error(payload)` before reading payload fields.

`is_error` is a built-in helper in the sandbox with a type-guard signature.
This avoids a known TypedDict narrowing limitation where direct
`"error" in payload` checks may fail static type checking.

```python
def expect_ok(result):
    if is_error(result):
        print("API error: " + result["error"])
        return None
    return result
```

### Patterns and examples

#### Metadata and function count

```python
meta = expect_ok(get_database_metadata())
if meta is not None:
    print("arch: " + meta["architecture"])

funcs = expect_ok(get_functions())
if funcs is not None:
    print("functions: " + str(len(funcs["functions"])))
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

#### Mutation call example

```python
set_result = set_comment_at(0x401000, "checked by analyst")
if set_result is not None and is_error(set_result):
    print("mutation failed: " + set_result["error"])
```

## Function reference

(Inserted dynamically from `ida_codemode_api.api_reference()`.)

## Tips

- Use `is_error(payload)` before reading payload fields.
- Read and mutation callbacks are both available; call mutators intentionally.
- Use `help("callback_name")` for callback-specific details.
- Prefer discovery callbacks (`get_functions`, `get_strings`, ...) over
  hardcoded addresses.
- Keep scripts focused; default timeout is 30 seconds.

## Resource limits

| Limit | Default |
|-------|---------|
| Timeout | 30 seconds |
| Memory | 100 MB |
| Recursion depth | 200 frames |
