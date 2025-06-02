isort:
    uvx isort --length-sort --profile black --line-length 120 idapro_plugin_manager scripts

black:
    uvx black --line-length 120 idapro_plugin_manager scripts

ruff:
    uvx ruff check --line-length 120 idapro_plugin_manager scripts

ty:
    uvx ty check --ignore unresolved-import

mypy:
    uvx mypy --check-untyped-defs --ignore-missing-imports idapro_plugin_manager scripts

lint:
    -just isort
    -just black
    -just ruff
    -just ty
    -just mypy
