isort:
    uvx isort --length-sort --profile black --line-length 120 hint_calls.py

black:
    uvx black --line-length 120 hint_calls.py

ruff:
    uvx ruff check --line-length 120 hint_calls.py

ty:
    uvx ty check --ignore unresolved-import hint_calls.py

mypy:
    uvx mypy --check-untyped-defs --ignore-missing-imports hint_calls.py

lint:
    -just isort
    -just black
    -just ruff
    -just ty
    -just mypy

clean:
    -rm -rf dist/ hint_calls_ida_plugin.egg-info/

build:
    python -m build --wheel
