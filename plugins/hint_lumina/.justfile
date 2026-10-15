ruff:
    uvx ruff check hint_lumina.py hint_lumina_entry.py tests

mypy:
    uvx mypy --check-untyped-defs --ignore-missing-imports hint_lumina.py hint_lumina_entry.py

test:
    ../../.venv/bin/python -m pytest -q tests

lint:
    -just ruff
    -just mypy
