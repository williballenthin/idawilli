import argparse
import tempfile
from pathlib import Path

from idapro_plugin_manager.__main__ import handle_mirror_command


def test_mirror_single_package():

    with tempfile.TemporaryDirectory() as temp_dir:
        args = argparse.Namespace()
        args.repo_dir = temp_dir
        args.package_names = ["idapro-plugin-manager"]

        result = handle_mirror_command(args)

        assert result == 0

        repo_path = Path(temp_dir)
        assert (repo_path / "index.html").exists()
        assert (repo_path / "packages").exists()

        for package in ["requests", "certifi", "urllib3", "charset-normalizer", "idna"]:
            assert (repo_path / package).exists(), f"Package {package} not found in {repo_path / 'packages'}"


def test_mirror_all():
    with tempfile.TemporaryDirectory() as temp_dir:
        args = argparse.Namespace()
        args.repo_dir = temp_dir
        args.package_names = []
        args.yes = True

        result = handle_mirror_command(args)

        assert result == 0

        repo_path = Path(temp_dir)
        assert (repo_path / "index.html").exists()
        assert (repo_path / "packages").exists()

        for package in ["basic-ida-plugin", "multifile-ida-plugin"]:
            assert (repo_path / package).exists(), f"Package {package} not found in {repo_path / 'packages'}"
