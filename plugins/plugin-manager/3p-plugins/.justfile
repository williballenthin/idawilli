import-hrdevhelper:
    java -jar copybara_deploy.jar copy.bara.sky --folder-dir=third_party/


import:
    just import-hrdevhelper


clean-hrdevhelper:
    rm -rf third_party/HRDevHelper


clean:
    just clean-hrdevhelper


build-hrdevhelper:
    python -m build --wheel third_party/HRDevHelper


build:
    just build-hrdevhelper

