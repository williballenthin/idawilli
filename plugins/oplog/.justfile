isort:
    uvx isort --length-sort --profile black --line-length 120 .

black:
    uvx black --line-length 120 .

ruff:
    uvx ruff check --line-length 120 .

ty:
    uvx ty check --ignore unresolved-import .

mypy:
    uvx mypy --check-untyped-defs --ignore-missing-imports .

lint:
    -just isort
    -just black
    -just ruff
    -just ty
    -just mypy
