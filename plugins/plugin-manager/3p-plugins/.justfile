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

build:
    just build-hrdevhelper
    just build-dereferencing
    just build-ida-terminal-plugin
    just build-lazyida
    just build-swiftstringinspector

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

test:
    just test-hrdevhelper
    just test-dereferencing
    just test-ida-terminal-plugin
    just test-lazyida
    just test-swiftstringinspector
