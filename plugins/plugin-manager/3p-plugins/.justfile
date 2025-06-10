import-hrdevhelper:
    java -jar copybara_deploy.jar copy.bara.sky --folder-dir=third_party/

import-dereferencing:
    java -jar copybara_deploy.jar copy.bara.sky deREFerencing --folder-dir=third_party/

import:
    just import-hrdevhelper
    just import-dereferencing


clean-hrdevhelper:
    rm -rf third_party/HRDevHelper

clean-dereferencing:
    rm -rf third_party/deREFerencing

clean:
    just clean-hrdevhelper
    just clean-dereferencing


build-hrdevhelper:
    python -m build --wheel third_party/HRDevHelper

build-dereferencing:
    python -m build --wheel third_party/deREFerencing

build:
    just build-hrdevhelper
    just build-dereferencing

