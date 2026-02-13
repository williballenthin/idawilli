# ida-codemode-api

Portable, JSON-safe analysis and mutation API for IDA Pro.

This package exposes a fixed map of callbacks (plain Python callables) intended for:

- sandboxed agent/tool execution,
- JSON-RPC style hosting,
- cross-language bindings (Python/JavaScript/etc.) with serializable payloads.

## Design contract

- No exceptions in API results: callbacks return either a success payload or `{"error": str}`.
- Read callbacks return `SuccessPayload | ApiError`.
- Mutation callbacks return `None | ApiError`.
- `api_types.py` is the source of truth for signatures, payload types, and docs.
- `prompts/api_reference.md` is generated output (do not edit by hand).

## Quickstart

```python
from ida_domain import Database
from ida_domain.database import IdaCommandOptions
from ida_codemode_api import create_api_from_database

options = IdaCommandOptions(auto_analysis=True, new_database=False)
with Database.open("/path/to/binary", options, save_on_close=False) as db:
    api = create_api_from_database(db)

    meta = api["get_database_metadata"]()
    if "error" in meta:
        raise RuntimeError(meta["error"])

    funcs = api["get_functions"]()
    if "error" not in funcs:
        print(funcs["functions"][0]["name"])
```

## API docs

- Authoritative declarations and docstrings: `ida_codemode_api/api_types.py`
- Generated reference table: `ida_codemode_api/prompts/api_reference.md`
- Runtime helper for progressive disclosure: `help(api_name)`

## Development

Use:

```bash
just all
```

This regenerates docs, runs lint (`ruff` + `ty`), and runs integration tests.
