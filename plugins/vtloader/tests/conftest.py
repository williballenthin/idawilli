import json
import os
import shutil
import sys
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

# The plugin directory holds the ``vtloader`` package and is what IDA puts on
# ``sys.path``; the tests import the package the same way IDA does.
PLUGIN_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PLUGIN_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pe import build_minimal_pe  # noqa: E402
from vtloader.options import PLUGIN_OPTIONS_NAME  # noqa: E402
from vtloader.settings import PLUGIN_NAME  # noqa: E402

VT_ARGS = '-T"vtloader"'
PMA_ARCHIVE = PLUGIN_ROOT / "tests" / "data" / "pma-lab01-01.zip"
PMA_PASSWORD = b"infected"


def find_ida_install_dir() -> Path | None:
    """Locate the IDA runtime directory from IDADIR or the idalib config written by hcli.

    On macOS the config holds the .app bundle; the kernel wants the directory that
    contains the IDA libraries, so descend into Contents/MacOS.
    """
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
    """Build an IDA user directory with license files and, optionally, one installed plugin."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "plugins").mkdir()
    (root / "loaders").mkdir()
    if plugin_root is not None:
        (root / "plugins" / "vtloader").symlink_to(plugin_root)
    for source in (Path.home() / ".idapro", idadir):
        for lic in source.glob("*.hexlic"):
            shutil.copy(lic, root / lic.name)
    return root


def pytest_configure(config):
    """Point idalib at an isolated IDAUSR whose only plugin is this directory.

    The plugin runs at ``import idapro`` and creates the loader link itself. Runs
    before any test module imports ``idapro``, which reads these variables at import.
    """
    idadir = find_ida_install_dir()
    if idadir is None:
        return
    os.environ["IDADIR"] = str(idadir)

    idausr = create_idausr(
        Path(tempfile.mkdtemp(prefix="vtloader-idausr-")), idadir, PLUGIN_ROOT
    )
    os.environ["IDAUSR"] = str(idausr)
    config._vtloader_idausr = idausr


def pytest_unconfigure(config):
    idausr = getattr(config, "_vtloader_idausr", None)
    if idausr is not None:
        shutil.rmtree(idausr, ignore_errors=True)


@pytest.fixture(scope="session")
def ida():
    """The ``idapro`` module, or a skip when idalib is unavailable."""
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
        pytest.skip(
            "idalib before IDA 9.2 does not accept the -T switch used to select a loader"
        )
    ida_registry.reg_write_int("EULA 90", 1)
    idapro.enable_console_messages(os.environ.get("VTLOADER_TEST_CONSOLE") == "1")
    return idapro


@pytest.fixture
def open_database(ida):
    """Open a file through idalib for the duration of a ``with`` block, then close without saving.

    idalib keeps ``-O`` plugin options from earlier opens in the same process, so an
    empty ``-Ovtloader:`` is appended whenever the caller passes none.
    """

    @contextmanager
    def _open(path: Path, args: str | None = None, save: bool = False) -> Iterator[int]:
        reset = f"-O{PLUGIN_OPTIONS_NAME}:"
        if args is None:
            args = reset
        elif reset not in args:
            args = f"{args} {reset}"
        rc = ida.open_database(str(path), True, args)
        try:
            yield rc
        finally:
            if rc == 0:
                ida.close_database(save)

    return _open


@pytest.fixture(scope="session")
def tiny_pe() -> bytes:
    return build_minimal_pe()


@pytest.fixture
def plugin_settings(ida) -> Iterator[Callable[[dict[str, str]], None]]:
    """Write vtloader settings into the temporary IDAUSR's ida-config.json for one test.

    ida-settings reads this file, so the loader sees the values exactly as it would
    in a configured installation. The plugin entry is removed afterwards.
    """
    config_path = Path(os.environ["IDAUSR"]) / "ida-config.json"

    def _write(settings: dict[str, str]) -> None:
        config = json.loads(config_path.read_text()) if config_path.exists() else {}
        config.setdefault("Plugins", {})[PLUGIN_NAME] = {"settings": settings}
        config_path.write_text(json.dumps(config))

    yield _write
    if config_path.exists():
        config = json.loads(config_path.read_text())
        config.get("Plugins", {}).pop(PLUGIN_NAME, None)
        config_path.write_text(json.dumps(config))
