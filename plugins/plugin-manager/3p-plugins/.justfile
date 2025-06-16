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

import-idafuzzy:
    python migrate_plugins.py IDAFuzzy

import-hexlight:
    python migrate_plugins.py hexlight

import-string-from-selection:
    python migrate_plugins.py string-from-selection

import-easy-nop:
    python migrate_plugins.py easy-nop

import-d810:
    python migrate_plugins.py d810

import-hexinlay:
    python migrate_plugins.py HexInlay

import-hex-highlighter:
    python migrate_plugins.py hex-highlighter

import-describekey:
    python migrate_plugins.py describekey

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

clean-idafuzzy:
    rm -rf third_party/IDAFuzzy

clean-hexlight:
    rm -rf third_party/hexlight

clean-string-from-selection:
    rm -rf third_party/string-from-selection

clean-easy-nop:
    rm -rf third_party/easy-nop

clean-d810:
    rm -rf third_party/d810

clean-hexinlay:
    rm -rf third_party/HexInlay

clean-hex-highlighter:
    rm -rf third_party/hex-highlighter

clean-describekey:
    rm -rf third_party/describekey

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

build-idafuzzy:
    python -m build --wheel third_party/IDAFuzzy

build-hexlight:
    python -m build --wheel third_party/hexlight

build-string-from-selection:
    python -m build --wheel third_party/string-from-selection

build-easy-nop:
    python -m build --wheel third_party/easy-nop

build-d810:
    python -m build --wheel third_party/d810

build-hexinlay:
    python -m build --wheel third_party/HexInlay

build-hex-highlighter:
    python -m build --wheel third_party/hex-highlighter

build-describekey:
    python -m build --wheel third_party/describekey

build:
    just build-hrdevhelper
    just build-dereferencing
    just build-ida-terminal-plugin
    just build-lazyida
    just build-swiftstringinspector
    just build-xrefer
    just build-hexrayspytools
    just build-idafuzzy
    just build-hexlight
    just build-string-from-selection
    just build-easy-nop
    just build-d810
    just build-hexinlay
    just build-hex-highlighter
    just build-describekey

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

test-idafuzzy:
    python ../scripts/test_plugin.py third_party/IDAFuzzy/dist/*.whl

test-hexlight:
    python ../scripts/test_plugin.py third_party/hexlight/dist/*.whl

test-string-from-selection:
    python ../scripts/test_plugin.py third_party/string-from-selection/dist/*.whl

test-easy-nop:
    python ../scripts/test_plugin.py third_party/easy-nop/dist/*.whl

test-d810:
    python ../scripts/test_plugin.py third_party/d810/dist/*.whl

test-hexinlay:
    python ../scripts/test_plugin.py third_party/HexInlay/dist/*.whl

test-hex-highlighter:
    python ../scripts/test_plugin.py third_party/hex-highlighter/dist/*.whl

test-describekey:
    python ../scripts/test_plugin.py third_party/describekey/dist/*.whl

test:
    just test-hrdevhelper
    just test-dereferencing
    just test-ida-terminal-plugin
    just test-lazyida
    just test-swiftstringinspector
    just test-xrefer
    just test-hexrayspytools
    just test-idafuzzy
    just test-hexlight
    just test-string-from-selection
    just test-easy-nop
    just test-d810
    just test-hexinlay
    just test-hex-highlighter
    just test-describekey

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
