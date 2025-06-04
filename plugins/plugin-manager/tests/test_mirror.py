import tempfile
from typing import Any
from pathlib import Path

import pytest

from idapro_plugin_manager import mirror


@pytest.fixture(scope="function")
def temp_repo_dir():
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


def test_get_dependencies_basic():
    """Test basic dependency extraction."""
    package_info = {"info": {"requires_dist": ["dependency1>=1.0", "dependency2"]}}
    deps = mirror.get_dependencies(package_info)
    assert "dependency1" in deps
    assert "dependency2" in deps
    assert len(deps) == 2


def test_get_dependencies_empty():
    """Test handling of packages with no dependencies."""
    package_info = {"info": {"requires_dist": None}}
    deps = mirror.get_dependencies(package_info)
    assert len(deps) == 0


def test_get_dependencies_with_extras():
    """Test that only base dependencies are included, not extras."""
    package_info = {"info": {"requires_dist": ["dependency1>=1.0", "optional-dep; extra == 'dev'"]}}
    deps = mirror.get_dependencies(package_info)
    assert "dependency1" in deps
    assert "optional-dep" not in deps


def test_get_latest_version_files_basic():
    """Test getting files for latest version."""
    package_info = {
        "releases": {
            "1.0.0": [
                {"filename": "test_package-1.0.0-py3-none-any.whl", "yanked": False},
                {"filename": "test-package-1.0.0.tar.gz", "yanked": False},
            ]
        }
    }
    files = mirror.get_latest_version_files(package_info)
    assert len(files) == 2
    assert any(f["filename"] == "test_package-1.0.0-py3-none-any.whl" for f in files)
    assert any(f["filename"] == "test-package-1.0.0.tar.gz" for f in files)


def test_get_latest_version_files_no_releases():
    """Test handling of packages with no releases."""
    package_info: dict[str, Any] = {"releases": {}}
    files = mirror.get_latest_version_files(package_info)
    assert len(files) == 0


def test_get_latest_version_files_multiple_versions():
    """Test that only latest version files are returned."""
    package_info = {
        "releases": {
            "1.0.0": [{"filename": "old-1.0.0.whl", "yanked": False}],
            "2.0.0": [{"filename": "new-2.0.0.whl", "yanked": False}],
            "1.5.0": [{"filename": "mid-1.5.0.whl", "yanked": False}],
        }
    }
    files = mirror.get_latest_version_files(package_info)
    assert len(files) == 1
    assert files[0]["filename"] == "new-2.0.0.whl"


def test_create_package_index_basic(temp_repo_dir):
    """Test creating a package index page."""
    files_info = [{"filename": "test-1.0.0.whl", "hash": "abc123"}, {"filename": "test-1.0.0.tar.gz", "hash": "def456"}]

    mirror.create_package_index(temp_repo_dir, "test-package", files_info)

    index_file = temp_repo_dir / "test-package" / "index.html"
    assert index_file.exists()

    content = index_file.read_text()
    assert "test-1.0.0.whl" in content
    assert "test-1.0.0.tar.gz" in content
    assert "sha256=abc123" in content
    assert "sha256=def456" in content


def test_create_root_index_basic(temp_repo_dir):
    """Test creating the root index page."""
    package_names = ["package1", "package2", "test-package"]

    mirror.create_root_index(temp_repo_dir, package_names)

    index_file = temp_repo_dir / "index.html"
    assert index_file.exists()

    content = index_file.read_text()
    assert "package1" in content
    assert "package2" in content
    assert "test-package" in content

    # Check that links are properly formed
    assert 'href="package1/"' in content
    assert 'href="package2/"' in content
    assert 'href="test-package/"' in content


def test_html_escaping(temp_repo_dir):
    """Test that special characters are properly HTML escaped."""
    package_names = ["<script>alert('test')</script>"]
    mirror.create_root_index(temp_repo_dir, package_names)

    content = (temp_repo_dir / "index.html").read_text()

    assert "&lt;script&gt;" in content
    assert "<script>" not in content


def test_mirror_real_package(temp_repo_dir):
    """Test mirroring a real package - idapro-plugin-manager."""
    mirror.mirror_packages(temp_repo_dir, ["idapro-plugin-manager"])

    assert (temp_repo_dir / "index.html").exists()
    assert (temp_repo_dir / "idapro-plugin-manager" / "index.html").exists()
    assert (temp_repo_dir / "packages").exists()

    root_content = (temp_repo_dir / "index.html").read_text()
    assert "idapro-plugin-manager" in root_content
    assert 'href="idapro-plugin-manager/"' in root_content

    pkg_content = (temp_repo_dir / "idapro-plugin-manager" / "index.html").read_text()
    assert "idapro_plugin_manager" in pkg_content
    assert "sha256=" in pkg_content

    packages_dir = temp_repo_dir / "packages"
    all_files = list(packages_dir.glob("*"))

    assert len(all_files) >= 2, f"Expected at least 2 files, found: {len(all_files)}"

    main_pkg_files = [f for f in all_files if "idapro_plugin_manager" in f.name]
    assert len(main_pkg_files) >= 1, f"Expected main package files, found: {main_pkg_files}"


def test_mirror_multiple_packages(temp_repo_dir):
    """Test mirroring multiple packages."""
    mirror.mirror_packages(temp_repo_dir, ["idapro-plugin-manager", "packaging"])

    assert (temp_repo_dir / "index.html").exists()
    assert (temp_repo_dir / "packages").exists()

    root_content = (temp_repo_dir / "index.html").read_text()
    assert "idapro-plugin-manager" in root_content
    assert "packaging" in root_content

    packages_dir = temp_repo_dir / "packages"
    all_files = list(packages_dir.glob("*"))

    assert len(all_files) >= 4, f"Expected at least 4 files, found: {len(all_files)}"

    ida_files = [f for f in all_files if "idapro_plugin_manager" in f.name]
    packaging_files = [f for f in all_files if "packaging" in f.name]
    assert len(ida_files) >= 1, f"Expected IDA package files, found: {ida_files}"
    assert len(packaging_files) >= 1, f"Expected packaging files, found: {packaging_files}"
