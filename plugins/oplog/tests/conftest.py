import os
import json
import shutil
import tempfile
import subprocess
from pathlib import Path

import pytest


PLUGIN_DIR = Path(__file__).parent.parent
REPO_ROOT = PLUGIN_DIR.parent.parent
TEST_BINARY = REPO_ROOT / "tests" / "data" / "Practical Malware Analysis Lab 01-01.exe_"
DEFAULT_IDAUSR = Path.home() / ".idapro"


@pytest.fixture(scope="session")
def test_binary() -> Path:
    assert TEST_BINARY.exists(), f"Test binary not found: {TEST_BINARY}"
    return TEST_BINARY


@pytest.fixture
def work_dir(tmp_path: Path) -> Path:
    return tmp_path


def get_ida_install_dir() -> str:
    source_config = DEFAULT_IDAUSR / "ida-config.json"
    if source_config.exists():
        data = json.loads(source_config.read_text())
        return data.get("Paths", {}).get("ida-install-dir", "")
    raise RuntimeError("Could not find IDA install directory in ~/.idapro/ida-config.json")


@pytest.fixture
def temp_idauser(tmp_path: Path) -> Path:
    idauser = tmp_path / "idauser"
    idauser.mkdir()
    (idauser / "plugins").mkdir()

    for hexlic in DEFAULT_IDAUSR.glob("*.hexlic"):
        shutil.copy(hexlic, idauser / hexlic.name)

    env = os.environ.copy()
    env["HCLI_IDAUSR"] = str(idauser)

    ida_install_dir = get_ida_install_dir()
    result = subprocess.run(
        ["uv", "run", "--with", "ida-hcli>=0.15", "hcli", "ida", "set-default", ida_install_dir],
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"hcli ida set-default failed:\nstdout: {result.stdout}\nstderr: {result.stderr}")

    accept_eula_script = '''
import idapro
import ida_registry
ida_registry.reg_write_int("EULA 90", 1)
ida_registry.reg_write_int("AutoUseLumina", 0)
ida_registry.reg_write_int("AutoCheckUpdates", 0)
'''
    result = subprocess.run(
        ["python", "-c", accept_eula_script],
        env={"IDAUSR": str(idauser), **os.environ},
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"EULA acceptance failed:\nstdout: {result.stdout}\nstderr: {result.stderr}")

    plugin_zip = tmp_path / "oplog.zip"
    shutil.make_archive(
        str(plugin_zip.with_suffix("")),
        "zip",
        root_dir=PLUGIN_DIR,
        base_dir=".",
    )

    result = subprocess.run(
        ["uv", "run", "--with", "ida-hcli>=0.15", "hcli", "plugin", "install", str(plugin_zip)],
        env=env,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        pytest.fail(f"hcli plugin install failed:\nstdout: {result.stdout}\nstderr: {result.stderr}")

    return idauser


def run_ida_script(
    binary_path: Path,
    script: str,
    idauser: Path,
    work_dir: Path,
    timeout: int = 120,
) -> subprocess.CompletedProcess:
    import textwrap

    env = os.environ.copy()
    env["IDAUSR"] = str(idauser)

    indented_script = textwrap.indent(textwrap.dedent(script), "    ")

    script_file = work_dir / "ida_script.py"
    script_file.write_text(f'''
import sys
import traceback

try:
    import idapro
    print("Opening database...", file=sys.stderr)
    idapro.open_database("{binary_path}", run_auto_analysis=True)
    print("Database opened, running script...", file=sys.stderr)

{indented_script}

    print("Script complete, closing database...", file=sys.stderr)
    idapro.close_database()
    print("Done.", file=sys.stderr)
except Exception as e:
    traceback.print_exc()
    sys.exit(1)
''')

    result = subprocess.run(
        ["python", str(script_file)],
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(work_dir),
    )

    return result
