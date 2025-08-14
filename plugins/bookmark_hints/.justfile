isort:
    uvx isort --length-sort --profile black --line-length 120 bookmark_hints.py

black:
    uvx black --line-length 120 bookmark_hints.py

ruff:
    uvx ruff check --line-length 120 bookmark_hints.py

ty:
    uvx ty check --ignore unresolved-import

mypy:
    uvx mypy --check-untyped-defs --ignore-missing-imports bookmark_hints.py

lint:
    -just isort
    -just black
    -just ruff
    -just ty
    -just mypy
