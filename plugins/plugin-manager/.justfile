isort:
    uvx isort --length-sort --profile black --line-length 120 idapro_plugin_manager

black:
    uvx black --line-length 120 idapro_plugin_manager

ruff:
    uvx ruff check --line-length 120 idapro_plugin_manager

ty:
    uvx ty check --ignore unresolved-import

mypy:
    uvx mypy --check-untyped-defs --ignore-missing-imports --disable-error-code=import-untyped idapro_plugin_manager

lint:
    -just isort
    -just black
    -just ruff
    -just ty
    -just mypy
