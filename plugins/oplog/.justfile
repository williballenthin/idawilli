isort:
    uvx isort --length-sort --profile black --line-length 120 .

black:
    uvx black --line-length 120 .

ruff:
    uvx ruff check --line-length 120 .

mypy:
    uvx mypy --check-untyped-defs --ignore-missing-imports .

lint:
    -just isort
    -just black
    -just ruff
    -just mypy
