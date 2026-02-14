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

For reliability, prefer explicit loops and simple control flow over brittle
one-liners (`next(...)`, heavy comprehensions, unnecessary `sorted(...)`).

**Not available**: `import`, `open()`, `eval()`, `exec()`,
`__import__`, `os`, `sys`, `subprocess`, or any I/O.

### Type checker contract (strict)

A strict static type checker runs before execution. Treat typing warnings/errors
as blocking and fix them before adding more analysis logic.

`expect_ok(payload)` returns either a success payload or `None`. Always guard
with `if x is None: ... else: ...` before any `x[...]` or method access.

Prefer direct key access after `None` checks (for example `meta["entry_point"]`)
instead of optional/dynamic access patterns on uncertain values.

### API call pattern

Each callback returns either:

- a success payload
- `{"error": "..."}`

Use `expect_ok(payload)` as the primary pattern for API calls that are likely
to succeed.

Use `is_error(payload)` when you need explicit error-branch handling. `is_error`
is a built-in type-guard helper in the sandbox.

Avoid direct `"error" in payload` checks for static type narrowing.

Every script should call at least one IDA callback and print concrete evidence.
Do not send placeholder literals/lists that do not query the database.

### Patterns and examples

#### Safe single-call template

```python
meta = expect_ok(get_database_metadata())
if meta is None:
    print("get_database_metadata failed")
else:
    print("arch: " + meta["architecture"])
```

#### Safe multi-call template

```python
funcs = expect_ok(get_functions())
strings_res = expect_ok(get_strings())

if funcs is not None:
    print("functions: " + str(len(funcs["functions"])))
if strings_res is not None:
    print("strings: " + str(len(strings_res["strings"])))
```

#### Safe chained-call template

```python
funcs = expect_ok(get_functions())
if funcs is not None and len(funcs["functions"]) > 0:
    first = funcs["functions"][0]
    decomp = expect_ok(decompile_function_at(first["address"]))
    if decomp is not None:
        for line in decomp["pseudocode"][:20]:
            print(line)
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

#### Check callback docs before first use

```python
help_result = expect_ok(help("decompile_function_at"))
if help_result is not None:
    print(help_result["documentation"])
```

#### Avoid this anti-pattern

```python
# bad: unsafe, because expect_ok(...) may return None
funcs = expect_ok(get_functions())
print(funcs["functions"])  # do not do this
```

Prefer `decompile_function_at(...)` when possible: pseudocode is usually
more concise and carries higher-level semantic information than raw assembly.
Use disassembly when you need exact instruction-level details.

`get_function_disassembly_at(...)["disassembly"]` and
`decompile_function_at(...)["pseudocode"]` are both `list[str]`.
Use slicing/iteration directly; do not call `.splitlines()` on them.

## Function reference

(Inserted dynamically from `ida_codemode_api.api_reference()`.)

## Tips

- The static checker is strict: treat typing warnings/errors as blocking.
- Prefer `expect_ok(payload)` for likely-success calls; use `is_error(payload)` when branching on failure details.
- For every `x = expect_ok(...)`, guard with `if x is not None:` before any `x[...]` access.
- On typing failures, make the smallest possible fix and rerun; do not rewrite the whole script.
- Prefer decompilation (`decompile_function_at`) over disassembly for most analysis tasks: it is usually more concise and higher signal.
- Prefer explicit loops over brittle one-liners (`next(...)`, heavy comprehensions, unnecessary `sorted(...)`).
- Read and mutation callbacks are both available; call mutators intentionally.
- Use `help("callback_name")` before first use when payload shape is uncertain.
- Prefer discovery callbacks (`get_functions`, `get_strings`, ...) over
  hardcoded addresses.
- Every script should print concrete evidence from callback output.
- Keep scripts focused; default timeout is 30 seconds.

## Resource limits

| Limit | Default |
|-------|---------|
| Timeout | 30 seconds |
| Memory | 100 MB |
| Recursion depth | 200 frames |
