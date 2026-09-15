import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PLUGIN_ROOT))


def find_ida_install_dir() -> Path | None:
    path: Path | None = None
    if os.environ.get("IDADIR"):
        path = Path(os.environ["IDADIR"])
    else:
        config = Path.home() / ".idapro" / "ida-config.json"
        if config.is_file():
            value = (
                json.loads(config.read_text()).get("Paths", {}).get("ida-install-dir")
            )
            if value:
                path = Path(value)
    if (
        path is not None
        and path.suffix == ".app"
        and (path / "Contents" / "MacOS").is_dir()
    ):
        path = path / "Contents" / "MacOS"
    return path


def create_idausr(root: Path, idadir: Path, plugin_root: Path | None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "plugins").mkdir()
    if plugin_root is not None:
        (root / "plugins" / "flirt-data-pack").symlink_to(plugin_root)
    for source in (Path.home() / ".idapro", idadir):
        for lic in source.glob("*.hexlic"):
            shutil.copy(lic, root / lic.name)
    return root


def pytest_configure(config):
    idadir = find_ida_install_dir()
    if idadir is None:
        return
    os.environ["IDADIR"] = str(idadir)

    idausr = create_idausr(
        Path(tempfile.mkdtemp(prefix="flirt-data-pack-idausr-")), idadir, PLUGIN_ROOT
    )
    os.environ["IDAUSR"] = str(idausr)
    config._flirt_data_pack_idausr = idausr


def pytest_unconfigure(config):
    idausr = getattr(config, "_flirt_data_pack_idausr", None)
    if idausr is not None:
        shutil.rmtree(idausr, ignore_errors=True)


@pytest.fixture(scope="session")
def ida():
    if "IDAUSR" not in os.environ or "IDADIR" not in os.environ:
        pytest.skip(
            "no IDA installation configured (set IDADIR or ~/.idapro/ida-config.json)"
        )
    try:
        import idapro
    except ImportError as e:
        pytest.skip(f"idalib not importable: {e}")
    import ida_pro
    import ida_registry

    if ida_pro.IDA_SDK_VERSION < 920:
        pytest.skip("idalib before IDA 9.2 is not supported")
    ida_registry.reg_write_int("EULA 90", 1)
    idapro.enable_console_messages(
        os.environ.get("FLIRT_DATA_PACK_TEST_CONSOLE") == "1"
    )
    return idapro
