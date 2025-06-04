isort:
    uvx isort --length-sort --profile black --line-length 120 idapro_plugin_manager tests/

black:
    uvx black --line-length 120 idapro_plugin_manager tests/

ruff:
    uvx ruff check --line-length 120 idapro_plugin_manager tests/

ty:
    uvx ty check --ignore unresolved-import idapro_plugin_manager tests/

mypy:
    uvx mypy --check-untyped-defs --ignore-missing-imports --disable-error-code=import-untyped idapro_plugin_manager tests/

lint:
    -just isort
    -just black
    -just ruff
    -just ty
    -just mypy

test:
    pytest tests/
