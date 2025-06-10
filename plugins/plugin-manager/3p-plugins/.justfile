import-hrdevhelper:
    python migrate_plugins.py HRDevHelper

import-dereferencing:
    python migrate_plugins.py deREFerencing

import:
    python migrate_plugins.py

clean-hrdevhelper:
    rm -rf third_party/HRDevHelper

clean-dereferencing:
    rm -rf third_party/deREFerencing

clean:
    rm -rf third_party/

build-hrdevhelper:
    python -m build --wheel third_party/HRDevHelper

build-dereferencing:
    python -m build --wheel third_party/deREFerencing

build:
    just build-hrdevhelper
    just build-dereferencing
