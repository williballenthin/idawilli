import-hrdevhelper:
    python migrate_plugins.py HRDevHelper

import-dereferencing:
    python migrate_plugins.py deREFerencing

import-ida-terminal-plugin:
    python migrate_plugins.py ida-terminal-plugin

import-lazyida:
    python migrate_plugins.py LazyIDA

import-swiftstringinspector:
    python migrate_plugins.py SwiftStringInspector

import-xrefer:
    python migrate_plugins.py xrefer

import-hexrayspytools:
    python migrate_plugins.py HexRaysPyTools

import:
    python migrate_plugins.py

clean-hrdevhelper:
    rm -rf third_party/HRDevHelper

clean-dereferencing:
    rm -rf third_party/deREFerencing

clean-ida-terminal-plugin:
    rm -rf third_party/ida-terminal-plugin

clean-lazyida:
    rm -rf third_party/LazyIDA

clean-swiftstringinspector:
    rm -rf third_party/SwiftStringInspector

clean-xrefer:
    rm -rf third_party/xrefer

clean-hexrayspytools:
    rm -rf third_party/HexRaysPyTools

clean:
    rm -rf third_party/

build-hrdevhelper:
    python -m build --wheel third_party/HRDevHelper

build-dereferencing:
    python -m build --wheel third_party/deREFerencing

build-ida-terminal-plugin:
    python -m build --wheel third_party/ida-terminal-plugin

build-lazyida:
    python -m build --wheel third_party/LazyIDA

build-swiftstringinspector:
    python -m build --wheel third_party/SwiftStringInspector

build-xrefer:
    python -m build --wheel third_party/xrefer

build-hexrayspytools:
    python -m build --wheel third_party/HexRaysPyTools

build:
    just build-hrdevhelper
    just build-dereferencing
    just build-ida-terminal-plugin
    just build-lazyida
    just build-swiftstringinspector
    just build-xrefer
    just build-hexrayspytools

test-hrdevhelper:
    python ../scripts/test_plugin.py third_party/HRDevHelper/dist/*.whl

test-dereferencing:
    python ../scripts/test_plugin.py third_party/deREFerencing/dist/*.whl

test-ida-terminal-plugin:
    python ../scripts/test_plugin.py third_party/ida-terminal-plugin/dist/*.whl

test-lazyida:
    python ../scripts/test_plugin.py third_party/LazyIDA/dist/*.whl

test-swiftstringinspector:
    python ../scripts/test_plugin.py third_party/SwiftStringInspector/dist/*.whl

test-xrefer:
    python ../scripts/test_plugin.py third_party/xrefer/dist/*.whl

test-hexrayspytools:
    python ../scripts/test_plugin.py third_party/HexRaysPyTools/dist/*.whl

test:
    just test-hrdevhelper
    just test-dereferencing
    just test-ida-terminal-plugin
    just test-lazyida
    just test-swiftstringinspector
    just test-xrefer
    just test-hexrayspytools

isort:
    uvx isort --length-sort --profile black --line-length 120 migrate_plugins.py

black:
    uvx black --line-length 120 migrate_plugins.py

ruff:
    uvx ruff check --line-length 120 migrate_plugins.py

ty:
    uvx ty check --ignore unresolved-import migrate_plugins.py

mypy:
    uvx mypy --check-untyped-defs --ignore-missing-imports --disable-error-code=import-untyped migrate_plugins.py

lint:
    -just isort
    -just black
    -just ruff
    -just ty
    -just mypy
