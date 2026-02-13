The entire API must be designed to be highly portable: exposed in Python, JavaScript, and other host languages.
No exceptions, iterators, or non-serializable objects.

Each API function must have:
- declaration in `api_types.py`
- definition in `api.py`

`api_types.py` type hints and docstrings are the source of truth for API docs.
`api_reference.md` is generated output, never the source of truth.

## Ty contract pattern (authoritative)

Use this minimal pattern so `ty` verifies declaration/implementation drift:

- In `api_types.py`, define per-function callable aliases:
  - `GetFooResult = FooOk | ApiError`
  - `GetFooFn = Callable[[int], GetFooResult]` (example)
- In `api_types.py`, define an API map contract:
  - `class ApiFunctions(TypedDict): get_foo: GetFooFn`
- Keep per-function declarations in `api_types.py` (for docs/source-of-truth), but use concrete bodies:
  - `def get_foo(address: int) -> GetFooResult: raise NotImplementedError`
- In `api.py`:
  - annotate `create_api_from_database(...) -> api_types.ApiFunctions`
  - annotate each implementation with explicit arg/return types matching the callable alias
  - annotate the returned map as `api: api_types.ApiFunctions = {...}`
- Do **not** import function declaration symbols from `api_types.py` into `api.py` and redefine them.
  This causes redefinition/unused-import lint errors and does not help `ty` enforce signature matching.

Minimal sketch:

```py
# api_types.py
from typing import Callable, TypedDict

GetFooResult = FooOk | ApiError
GetFooFn = Callable[[int], GetFooResult]

class ApiFunctions(TypedDict):
    get_foo: GetFooFn

def get_foo(address: int) -> GetFooResult:
    raise NotImplementedError
```

```py
# api.py
def create_api_from_database(db: Any) -> api_types.ApiFunctions:
    def get_foo(address: int) -> api_types.GetFooResult:
        ...

    api: api_types.ApiFunctions = {
        "get_foo": get_foo,
    }
    return api
```

## Result conventions (authoritative)

- Every API function returns `SuccessPayload | ApiError`.
- `ApiError` shape is exactly:

  ```py
  {"error": str}
  ```

- Callers detect failures by checking for presence of the `error` key.
- Do not use generic payload keys like `item`, `items`, or `value`.
  - Single structured objects are returned directly (raw object payload).
  - List returns use semantic keys (`functions`, `callers`, `segments`, etc.).
  - Scalar wrappers, when needed, use semantic keys (`name`, `comment`, `signature`, etc.).

## Documentation conventions

API documentation is derived from type hints + docstrings and is consumed by AI agents and users.

- Do not document per-function failure unions in the API reference table.
- API reference should state globally: each function returns either its success payload or `ApiError`.
- Render success payload types fully inline, including nested object/list element shapes.

Docstrings should be thorough and complete, ideally with real example payloads validated by tests.
API documentation is provided to AI agents and other users, and derived from the type hints and docstrings.
So these need to be great. Here's an example:

```py
# in api_types.py
def get_foo(address: int) -> Foo | ApiError:
  ...

# in api.py
def get_foo_at(address):
  """The foo at an address.

  Fetch a food at the given address. Call this when you want to know more about a Foo, such as when you are doing Bar.
  See also `get_bar_at` and `get_baz_at`.

  Example:
      for function_address in get_functions():
          foo = get_foo_at(function_address)["bar"]
          if "error" in foo: continue
          if foo["bar"] == "baz":
              print(foo["ping"])

  Args:
    address: the address

  Returns:
    A Foo (`{baz: str, ping: int, pong: list[int]}`) or ApiError on error.

  Example Foo:
      {
        "bar": "baz",
        "ping": 1,
        "pong": [1, 2, 3],
      }
  """
```

Use `just all` to rebuild docs, lint, and test after every change.
We're using `jj` for VCS for this project.
Use `gh` to fetch read-only information about the project/issues/etc.
