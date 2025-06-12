import-hrdevhelper:
    python migrate_plugins.py HRDevHelper

import-dereferencing:
    python migrate_plugins.py deREFerencing

import-ida-terminal-plugin:
    python migrate_plugins.py ida-terminal-plugin

import:
    python migrate_plugins.py

clean-hrdevhelper:
    rm -rf third_party/HRDevHelper

clean-dereferencing:
    rm -rf third_party/deREFerencing

clean-ida-terminal-plugin:
    rm -rf third_party/ida-terminal-plugin

clean:
    rm -rf third_party/

build-hrdevhelper:
    python -m build --wheel third_party/HRDevHelper

build-dereferencing:
    python -m build --wheel third_party/deREFerencing

build-ida-terminal-plugin:
    python -m build --wheel third_party/ida-terminal-plugin

build:
    just build-hrdevhelper
    just build-dereferencing
    just build-ida-terminal-plugin
