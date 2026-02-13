# ida-codemode-sandbox

A secure Monty-based execution sandbox for IDA Code Mode scripts.

This package wires:

- [`pydantic-monty`](https://github.com/pydantic/monty) (sandboxed Python execution)
- [`ida-codemode-api`](https://github.com/williballenthin/idawilli/tree/master/ida-codemode-api) (analysis + mutation callbacks)

The sandbox returns structured execution results (`SandboxResult`) and keeps
host-side controls for time, memory, and recursion limits.

## Quick start

```python
from ida_domain import Database
from ida_domain.database import IdaCommandOptions
from ida_codemode_sandbox import IdaSandbox

opts = IdaCommandOptions(auto_analysis=True, new_database=False)
with Database.open("sample.exe", opts, save_on_close=False) as db:
    sandbox = IdaSandbox(db)

    code = '''
def expect_ok(result):
    if "error" in result:
        print("API error: " + result["error"])
        return None
    return result

meta = expect_ok(get_database_metadata())
if meta is not None:
    print("arch: " + meta["architecture"])

funcs = expect_ok(get_functions())
if funcs is not None:
    print("function count: " + str(len(funcs["functions"])))
'''

    result = sandbox.run(code)
    if result.ok:
        print("".join(result.stdout), end="")
    else:
        print(result.error.formatted)
```

## Script pattern

Code inside the sandbox should treat API callbacks as returning either:

- success payload
- `{"error": "..."}`

Use a small helper and check for errors before reading payload fields:

```python
def expect_ok(result):
    if "error" in result:
        print("API error: " + result["error"])
        return None
    return result
```

## API docs

This repository intentionally does **not** duplicate callback docs.
Use the source of truth from `ida-codemode-api`:

- Runtime helper: `IdaSandbox.api_reference()`
- Runtime helper: `help("callback_name")` (inside sandbox code)
- Upstream project docs: `ida-codemode-api`

## Prompt helpers

- `IdaSandbox.system_prompt()` returns sandbox usage guidance plus the current
  `ida-codemode-api` function reference (inserted dynamically at runtime).
- `IdaSandbox.api_reference()` returns only the current function table.

## `execute()` adapter

`IdaSandbox.execute(code: str) -> str` is a convenience adapter for callers
expecting a plain string executor:

- on success: returns captured stdout
- on failure: returns a human-readable `Script error (...)` message

## Resource limits

Defaults:

- timeout: 30 seconds
- memory: 100 MB
- recursion depth: 200

Override at construction:

```python
import pydantic_monty

sandbox = IdaSandbox(
    db,
    limits=pydantic_monty.ResourceLimits(
        max_duration_secs=60.0,
        max_memory=200_000_000,
        max_recursion_depth=500,
    ),
)
```

## Running tests

```bash
python -m pytest -v
```
