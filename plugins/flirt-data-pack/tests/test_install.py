from pathlib import Path

from conftest import PLUGIN_ROOT
from flirt_data_pack.install import (
    LINK_PREFIX,
    get_procs,
    get_sig_sources,
    install_sig_links,
    is_our_link,
    link_name_for,
)


def make_plugin_root(
    tmp_path: Path, proc: str = "pc", sig_names: tuple[str, ...] = ("test.sig",)
) -> Path:
    root = tmp_path / "plugin"
    sig_dir = root / "sigs" / proc
    sig_dir.mkdir(parents=True)
    for name in sig_names:
        (sig_dir / name).write_bytes(b"IDASGN" + b"\x00" * 20)
    return root


class TestLinkNameFor:
    def test_prefixes_the_sig_name(self):
        assert link_name_for("vc32rtf.sig") == f"{LINK_PREFIX}vc32rtf.sig"

    def test_preserves_extension(self):
        assert link_name_for("custom.sig").endswith(".sig")


class TestGetSigSources:
    def test_finds_sig_files(self, tmp_path):
        root = make_plugin_root(tmp_path, sig_names=("a.sig", "b.sig"))
        sources = get_sig_sources(root, "pc")
        assert [s.name for s in sources] == ["a.sig", "b.sig"]

    def test_returns_empty_for_missing_proc(self, tmp_path):
        root = make_plugin_root(tmp_path, proc="pc")
        assert get_sig_sources(root, "arm") == []


class TestGetProcs:
    def test_finds_proc_directories(self, tmp_path):
        root = tmp_path / "plugin"
        for proc in ("pc", "arm"):
            (root / "sigs" / proc).mkdir(parents=True)
        assert get_procs(root) == ["arm", "pc"]

    def test_returns_empty_when_no_sigs_dir(self, tmp_path):
        assert get_procs(tmp_path / "nonexistent") == []


class TestInstallSigLinks:
    def test_creates_prefixed_symlinks(self, tmp_path):
        sig_dir = tmp_path / "sig" / "pc"
        root = make_plugin_root(tmp_path)

        paths = install_sig_links(sig_dir, root, "pc")

        assert len(paths) == 1
        link = paths[0]
        assert link.name == link_name_for("test.sig")
        assert link.is_symlink()
        assert link.resolve() == (root / "sigs" / "pc" / "test.sig").resolve()

    def test_creates_directory_if_missing(self, tmp_path):
        sig_dir = tmp_path / "deep" / "sig" / "pc"
        root = make_plugin_root(tmp_path)

        install_sig_links(sig_dir, root, "pc")

        assert sig_dir.is_dir()

    def test_is_idempotent(self, tmp_path):
        sig_dir = tmp_path / "sig" / "pc"
        root = make_plugin_root(tmp_path)

        paths_a = install_sig_links(sig_dir, root, "pc")
        inode = paths_a[0].lstat().st_ino
        paths_b = install_sig_links(sig_dir, root, "pc")

        assert paths_b[0].lstat().st_ino == inode

    def test_retargets_when_plugin_root_moves(self, tmp_path):
        sig_dir = tmp_path / "sig" / "pc"
        root_a = make_plugin_root(tmp_path / "a")
        root_b = make_plugin_root(tmp_path / "b")

        install_sig_links(sig_dir, root_a, "pc")
        install_sig_links(sig_dir, root_b, "pc")

        link = sig_dir / link_name_for("test.sig")
        assert link.resolve() == (root_b / "sigs" / "pc" / "test.sig").resolve()

    def test_installs_multiple_sigs(self, tmp_path):
        sig_dir = tmp_path / "sig" / "pc"
        root = make_plugin_root(tmp_path, sig_names=("alpha.sig", "beta.sig"))

        paths = install_sig_links(sig_dir, root, "pc")

        assert sorted(p.name for p in paths) == [
            link_name_for("alpha.sig"),
            link_name_for("beta.sig"),
        ]

    def test_does_not_replace_foreign_file(self, tmp_path):
        sig_dir = tmp_path / "sig" / "pc"
        sig_dir.mkdir(parents=True)
        foreign = sig_dir / link_name_for("test.sig")
        foreign.write_bytes(b"someone else's signature")
        root = make_plugin_root(tmp_path)

        paths = install_sig_links(sig_dir, root, "pc")

        assert paths == []
        assert foreign.read_bytes() == b"someone else's signature"

    def test_removes_stale_dangling_links(self, tmp_path):
        sig_dir = tmp_path / "sig" / "pc"
        sig_dir.mkdir(parents=True)
        root = make_plugin_root(tmp_path)
        stale = sig_dir / link_name_for("removed.sig")
        stale.symlink_to(root.resolve() / "sigs" / "pc" / "removed.sig")
        assert stale.is_symlink()
        assert not stale.exists()

        install_sig_links(sig_dir, root, "pc")

        assert not stale.is_symlink()

    def test_leaves_non_prefixed_links_alone(self, tmp_path):
        sig_dir = tmp_path / "sig" / "pc"
        sig_dir.mkdir(parents=True)
        other = sig_dir / "other_plugin_foo.sig"
        other.write_bytes(b"other plugin sig")
        root = make_plugin_root(tmp_path)

        install_sig_links(sig_dir, root, "pc")

        assert other.read_bytes() == b"other plugin sig"


class TestIsOurLink:
    def test_recognises_our_symlink(self, tmp_path):
        root = make_plugin_root(tmp_path)
        sig_dir = tmp_path / "sig" / "pc"
        sig_dir.mkdir(parents=True)
        link = sig_dir / link_name_for("test.sig")
        link.symlink_to((root / "sigs" / "pc" / "test.sig").resolve())

        assert is_our_link(link, root)

    def test_rejects_foreign_symlink(self, tmp_path):
        root = make_plugin_root(tmp_path)
        other_root = tmp_path / "other"
        other_sig = other_root / "sigs" / "pc" / "test.sig"
        other_sig.parent.mkdir(parents=True)
        other_sig.write_bytes(b"other")
        sig_dir = tmp_path / "sig" / "pc"
        sig_dir.mkdir(parents=True)
        link = sig_dir / link_name_for("test.sig")
        link.symlink_to(other_sig)

        assert not is_our_link(link, root)

    def test_rejects_non_prefixed_name(self, tmp_path):
        root = make_plugin_root(tmp_path)
        sig_dir = tmp_path / "sig" / "pc"
        sig_dir.mkdir(parents=True)
        link = sig_dir / "foreign_test.sig"
        link.symlink_to((root / "sigs" / "pc" / "test.sig").resolve())

        assert not is_our_link(link, root)


class TestRealPlugin:
    def test_plugin_ships_dummy_sig(self):
        sigs = get_sig_sources(PLUGIN_ROOT, "pc")
        assert any(s.name == "dummy.sig" for s in sigs)

    def test_dummy_sig_has_flirt_magic(self):
        dummy = PLUGIN_ROOT / "sigs" / "pc" / "dummy.sig"
        assert dummy.read_bytes()[:6] == b"IDASGN"

    def test_install_into_temp_dir(self, tmp_path):
        sig_dir = tmp_path / "sig" / "pc"

        paths = install_sig_links(sig_dir, PLUGIN_ROOT, "pc")

        assert len(paths) >= 1
        for p in paths:
            assert p.is_symlink()
            assert p.exists()
            assert p.name.startswith(LINK_PREFIX)
