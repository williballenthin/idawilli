import os
import subprocess
import sys
import textwrap
import types
import zipfile
from io import BytesIO
from pathlib import Path

from conftest import PLUGIN_ROOT, create_idausr
from memloader.install import (
    LINKS,
    LinkKind,
    get_link_target,
    install_loader_links,
    is_memloader_link,
    remove_loader_links,
)
from pe import build_minimal_pe


class BytesInput:
    """The subset of IDA's loader input protocol that ``accept_file`` uses."""

    def __init__(self, data: bytes):
        self._io = BytesIO(data)

    def seek(self, offset: int, whence: int = 0) -> int:
        return self._io.seek(offset, whence)

    def read(self, size: int) -> bytes:
        return self._io.read(size)

    def size(self) -> int:
        return len(self._io.getvalue())


def exec_loader_file(path: Path) -> dict:
    namespace: dict = {"__file__": str(path)}
    exec(compile(path.read_text(), str(path), "exec"), namespace)
    return namespace


def call_like_idapython(namespace: dict, name: str, *args):
    """IDAPython runs a loader function's code with the loader module's namespace as its globals."""
    return types.FunctionType(namespace[name].__code__, namespace)(*args)


def test_every_link_target_exists_in_the_plugin():
    for link in LINKS:
        target = get_link_target(PLUGIN_ROOT, link)
        assert target.is_file()
        assert target.name == link.filename


def test_install_creates_symlinks_into_plugin_root(tmp_path):
    loaders = tmp_path / "loaders"
    plugin_root = tmp_path / "plugins" / "memloader"
    plugin_root.mkdir(parents=True)

    created = install_loader_links(loaders, plugin_root)

    assert sorted(p.name for p in created) == sorted(link.filename for link in LINKS)
    for path in created:
        assert path.is_symlink()
        assert Path(os.readlink(path)) == plugin_root.resolve() / "loaders" / path.name
        assert is_memloader_link(path, plugin_root)


def test_install_can_hard_link_when_symlinks_are_not_permitted(tmp_path):
    loaders = tmp_path / "loaders"
    plugin_root = tmp_path / "plugin"
    (plugin_root / "loaders").mkdir(parents=True)
    for link in LINKS:
        get_link_target(plugin_root, link).write_text(
            '"""IDA loader entry for Memloader TEST."""\n'
        )

    created = install_loader_links(loaders, plugin_root, kinds=(LinkKind.HARDLINK,))

    for path in created:
        assert not path.is_symlink()
        assert os.path.samefile(path, plugin_root / "loaders" / path.name)
        assert is_memloader_link(path, plugin_root)

    inodes = {p: p.stat().st_ino for p in created}
    install_loader_links(loaders, plugin_root, kinds=(LinkKind.HARDLINK,))
    assert {p: p.stat().st_ino for p in created} == inodes

    target = get_link_target(plugin_root, LINKS[0])
    target.unlink()
    target.write_text('"""IDA loader entry for Memloader TEST, upgraded."""\n')
    install_loader_links(loaders, plugin_root, kinds=(LinkKind.HARDLINK,))
    assert os.path.samefile(created[0], target)
    assert len(remove_loader_links(loaders, plugin_root)) == len(LINKS)


def test_linked_loader_works_with_its_namespace_as_globals(ida, tmp_path):
    loaders = tmp_path / "loaders"
    (path,) = [p for p in install_loader_links(loaders, PLUGIN_ROOT) if "zip" in p.name]
    namespace = exec_loader_file(path)

    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.bin", b"payload")

    assert (
        call_like_idapython(
            namespace, "accept_file", BytesInput(buf.getvalue()), "x.zip"
        )
        == "Memloader ZIP"
    )
    assert (
        call_like_idapython(namespace, "accept_file", BytesInput(b"not a zip"), "x.bin")
        == 0
    )


OPEN_SCRIPT = textwrap.dedent(
    """
    import sys
    import idapro, ida_ida, ida_registry
    ida_registry.reg_write_int("EULA 90", 1)
    idapro.enable_console_messages(True)
    assert idapro.open_database(sys.argv[1], True, sys.argv[2]) == 0
    print("filetype", ida_ida.inf_get_filetype())
    idapro.close_database(False)
    """
)


def run_idalib(
    cwd: Path, idausr: Path, input_file: Path, args: str
) -> subprocess.CompletedProcess:
    """Open ``input_file`` in a separate idalib process that sees nothing but ``idausr``."""
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["IDAUSR"] = str(idausr)
    return subprocess.run(
        [sys.executable, "-c", OPEN_SCRIPT, str(input_file), args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
    )


def test_plugin_alone_makes_ida_find_the_loaders(ida, tmp_path):
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("sample.exe", build_minimal_pe())

    result = run_idalib(
        tmp_path, Path(os.environ["IDAUSR"]), archive, '-T"Memloader ZIP" -Omemloader:'
    )

    assert result.returncode == 0, result.stderr
    assert "filetype 11" in result.stdout
    assert all(
        (Path(os.environ["IDAUSR"]) / "loaders" / link.filename).is_symlink()
        for link in LINKS
    )


def test_orphaned_hard_link_stays_inert_and_asks_for_cleanup(ida, tmp_path):
    """After uninstall on Windows the hard-linked entry file survives without the package."""
    idausr = create_idausr(
        tmp_path / "idausr", Path(os.environ["IDADIR"]), plugin_root=None
    )
    for link in LINKS:
        os.link(get_link_target(PLUGIN_ROOT, link), idausr / "loaders" / link.filename)
    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_minimal_pe())

    result = run_idalib(tmp_path, idausr, sample, "-Omemloader:")

    assert result.returncode == 0, result.stderr
    assert "filetype 11" in result.stdout
    assert "Traceback" not in result.stdout + result.stderr
    for link in LINKS:
        assert f"Delete {idausr}/loaders/{link.filename}" in result.stdout


def test_install_is_idempotent_and_retargets_when_root_moves(tmp_path):
    loaders = tmp_path / "loaders"
    root_a = tmp_path / "a"
    root_b = tmp_path / "b"
    root_a.mkdir()
    root_b.mkdir()

    first = install_loader_links(loaders, root_a)
    inodes = {p: p.lstat().st_ino for p in first}
    install_loader_links(loaders, root_a)
    assert {p: p.lstat().st_ino for p in first} == inodes

    install_loader_links(loaders, root_b)
    for path in first:
        assert Path(os.readlink(path)).parent.parent == root_b.resolve()


def test_install_replaces_generated_stub_files_from_older_versions(tmp_path):
    loaders = tmp_path / "loaders"
    loaders.mkdir()
    old = loaders / "memloader_zip_loader.py"
    old.write_text("# Generated by the Memloader plugin.\n")
    plugin_root = tmp_path / "plugin"
    plugin_root.mkdir()

    install_loader_links(loaders, plugin_root)

    assert old.is_symlink()
    assert Path(os.readlink(old)).parent.parent == plugin_root.resolve()


def test_install_removes_stale_links_but_leaves_foreign_files(tmp_path):
    loaders = tmp_path / "loaders"
    loaders.mkdir()
    plugin_root = tmp_path / "plugin"
    (plugin_root / "loaders").mkdir(parents=True)
    stale = loaders / "memloader_old_loader.py"
    stale.symlink_to(plugin_root / "loaders" / "memloader_old_loader.py")
    dangling = loaders / "memloader_removed_loader.py"
    dangling.symlink_to(
        tmp_path / "elsewhere" / "loaders" / "memloader_removed_loader.py"
    )
    foreign_target = tmp_path / "mine.py"
    foreign_target.write_text("x = 1\n")
    foreign_link = loaders / "memloader_mine.py"
    foreign_link.symlink_to(foreign_target)
    foreign_file = loaders / "memloader_other.py"
    foreign_file.write_text("def accept_file(li, f):\n    return 0\n")

    install_loader_links(loaders, plugin_root)

    assert not stale.is_symlink()
    assert not dangling.is_symlink()
    assert foreign_link.is_symlink()
    assert foreign_file.is_file()
    assert (loaders / "memloader_zip_loader.py").is_symlink()


def test_remove_only_deletes_links_into_plugin_root(tmp_path):
    loaders = tmp_path / "loaders"
    plugin_root = tmp_path / "plugin"
    plugin_root.mkdir()
    install_loader_links(loaders, plugin_root)
    foreign_target = tmp_path / "mine.py"
    foreign_target.write_text("x = 1\n")
    foreign = loaders / "memloader_mine.py"
    foreign.symlink_to(foreign_target)

    removed = remove_loader_links(loaders, plugin_root)

    assert len(removed) == len(LINKS)
    assert foreign.is_symlink()
    assert not any(is_memloader_link(p, plugin_root) for p in loaders.iterdir())
