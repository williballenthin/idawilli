isort:
    uvx isort --length-sort --profile black --line-length 120 activity_log.py

black:
    uvx black --line-length 120 activity_log.py

ruff:
    uvx ruff check --line-length 120 activity_log.py

ty:
    uvx ty check --ignore unresolved-import

mypy:
    uvx mypy --check-untyped-defs --ignore-missing-imports activity_log.py

lint:
    -just isort
    -just black
    -just ruff
    -just ty
    -just mypy
