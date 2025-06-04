from __future__ import annotations

import os
import re
import html
import shutil
import hashlib
import tempfile
import urllib.parse
from typing import Any
from pathlib import Path

import requests
import packaging.version
import packaging.requirements
from rich.progress import TaskID, Progress


def normalize_name(name: str) -> str:
    """Normalize a project name according to PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


def get_package_info(session: requests.Session, package_name: str) -> dict[str, Any]:
    """Get package metadata from PyPI JSON API."""
    response = session.get(f"https://pypi.org/pypi/{package_name}/json")
    response.raise_for_status()
    return response.json()


def get_dependencies(package_info: dict[str, Any]) -> set[str]:
    """Extract dependencies from package metadata."""
    dependencies = set()

    requires_dist = package_info.get("info", {}).get("requires_dist")
    if requires_dist:
        for req_str in requires_dist:
            req = packaging.requirements.Requirement(req_str)
            if not req.marker or req.marker.evaluate():
                dependencies.add(req.name)

    return dependencies


def download_file(session: requests.Session, url: str, dest_path: Path, progress: Progress, task_id: TaskID) -> str:
    """Download a file and return its SHA256 hash."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        try:
            response = session.get(url, stream=True)
            response.raise_for_status()

            file_size = int(response.headers.get("content-length", 0))

            hasher = hashlib.sha256()
            downloaded = 0

            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    temp_file.write(chunk)
                    hasher.update(chunk)
                    downloaded += len(chunk)
                    if file_size > 0:
                        progress.update(task_id, completed=downloaded, total=file_size)

            shutil.move(temp_file.name, dest_path)
            return hasher.hexdigest()

        except Exception:
            if os.path.exists(temp_file.name):
                os.unlink(temp_file.name)
            raise


def get_latest_version_files(package_info: dict[str, Any]) -> list[dict[str, Any]]:
    """Get files for the latest version of a package."""
    releases = package_info.get("releases", {})
    if not releases:
        return []

    # Find latest version
    def version_sort_key(version_string: str) -> Any:
        try:
            return packaging.version.parse(version_string)
        except packaging.version.InvalidVersion:
            return packaging.version.Version("0.0.0alpha0")

    latest_version = max(releases.keys(), key=version_sort_key)
    return releases.get(latest_version, [])


def create_package_index(repo_dir: Path, package_name: str, files_info: list[dict[str, str]]) -> None:
    """Create PEP 503 compliant package index page."""
    normalized_name = normalize_name(package_name)
    package_dir = repo_dir / normalized_name
    package_dir.mkdir(parents=True, exist_ok=True)

    index_file = package_dir / "index.html"

    html_content = "<!DOCTYPE html>\n<html>\n<head>\n"
    html_content += f"<title>Links for {html.escape(package_name)}</title>\n"
    html_content += "</head>\n<body>\n"
    html_content += f"<h1>Links for {html.escape(package_name)}</h1>\n"

    for file_info in files_info:
        filename = file_info["filename"]
        file_hash = file_info["hash"]
        file_url = f"../../packages/{urllib.parse.quote(filename)}"

        html_content += f'<a href="{file_url}#sha256={file_hash}">{html.escape(filename)}</a><br/>\n'

    html_content += "</body>\n</html>\n"

    index_file.write_text(html_content)


def create_root_index(repo_dir: Path, package_names: list[str]) -> None:
    """Create PEP 503 compliant root index page."""
    index_file = repo_dir / "index.html"

    html_content = "<!DOCTYPE html>\n<html>\n<head>\n"
    html_content += "<title>Simple Index</title>\n"
    html_content += "</head>\n<body>\n"
    html_content += "<h1>Simple Index</h1>\n"

    for package_name in sorted(package_names):
        normalized_name = normalize_name(package_name)
        html_content += f'<a href="{urllib.parse.quote(normalized_name)}/">{html.escape(package_name)}</a><br/>\n'

    html_content += "</body>\n</html>\n"

    index_file.write_text(html_content)


def mirror_package(
    session: requests.Session, repo_dir: Path, package_name: str, progress: Progress, processed_packages: set[str]
) -> None:
    """Mirror a single package and its dependencies."""
    if package_name in processed_packages:
        return

    try:
        package_info = get_package_info(session, package_name)
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            progress.console.print(f"[yellow]Package '{package_name}' not found on PyPI[/]")
        else:
            raise e

    actual_name = package_info["info"]["name"]  # Use the canonical name from PyPI
    progress.console.print(f"Processing package: [cyan]{actual_name}[/]")

    files = get_latest_version_files(package_info)
    if not files:
        progress.console.print(f"[yellow]No files found for {actual_name}[/]")
        return

    packages_dir = repo_dir / "packages"
    packages_dir.mkdir(parents=True, exist_ok=True)

    files_info = []
    for file_data in files:
        if file_data.get("yanked", False):
            continue

        filename = file_data["filename"]
        file_url = file_data["url"]

        file_path = packages_dir / filename

        if file_path.exists():
            hasher = hashlib.sha256()
            hasher.update(file_path.read_bytes())
            sha256 = hasher.hexdigest()

        else:
            task_id = progress.add_task(f"Downloading {filename}", total=0)
            try:
                sha256 = download_file(session, file_url, file_path, progress, task_id)
            finally:
                progress.remove_task(task_id)

        files_info.append({"filename": filename, "hash": sha256})

    create_package_index(repo_dir, actual_name, files_info)
    processed_packages.add(package_name)

    dependencies = get_dependencies(package_info)
    for dep_name in dependencies:
        mirror_package(session, repo_dir, dep_name, progress, processed_packages)


def mirror_packages(repo_dir: Path, package_names: list[str]) -> None:
    """Mirror multiple packages and their dependencies to a local repository."""
    repo_dir = Path(repo_dir).resolve()
    repo_dir.mkdir(parents=True, exist_ok=True)

    session = requests.Session()
    session.headers.update({"User-Agent": "idapro-plugin-manager-mirror/1.0"})

    processed_packages: set[str] = set()

    with Progress() as progress:
        for package_name in package_names:
            mirror_package(session, repo_dir, package_name, progress, processed_packages)

        create_root_index(repo_dir, list(processed_packages))

        progress.console.print(f"\n[green]Successfully mirrored {len(processed_packages)} packages to {repo_dir}[/]")
        progress.console.print(
            f"Repository is PEP 503 compliant and can be used with: pip install -i file://{repo_dir} <package>"
        )
