# Derived from: https://github.com/pytest-dev/pytest/commit/fc115f06ea47daa7f6bea62930c78d1e896ce92b#diff-92e37f9ac8790b36b5e61bc942ca13939f4dacc25bca5f22719d8d0542cf9546 (MIT licensed)
#
# /// script
# dependencies = [
#   "packaging==24.2",
#   "platformdirs==4.3.7",
#   "requests==2.32.3",
#   "requests-cache==1.2.1",
#   "tabulate==0.9.0",
#   "rich==13.9.4",
# ]
# ///

# mypy: disallow-untyped-defs
from __future__ import annotations

import datetime
from typing import Any, TypedDict
from collections.abc import Iterator

import rich
import rich.table
import platformdirs
import packaging.version
from rich.progress import Progress
from requests_cache import SQLiteCache, CachedSession, CachedResponse, OriginalResponse

DEVELOPMENT_STATUS_CLASSIFIERS = (
    "Development Status :: 1 - Planning",
    "Development Status :: 2 - Pre-Alpha",
    "Development Status :: 3 - Alpha",
    "Development Status :: 4 - Beta",
    "Development Status :: 5 - Production/Stable",
    "Development Status :: 6 - Mature",
    "Development Status :: 7 - Inactive",
)
ADDITIONAL_PROJECTS: set[str] = set()


def get_project_with_refresh(
    session: CachedSession, name: str, last_serial: int
) -> OriginalResponse | CachedResponse:
    """Get a http cached pypi project

    force refresh in case of last serial mismatch
    """
    response = session.get(f"https://pypi.org/pypi/{name}/json")
    if int(response.headers.get("X-PyPI-Last-Serial", -1)) != last_serial:
        response = session.get(f"https://pypi.org/pypi/{name}/json", refresh=True)
    return response


def get_session() -> CachedSession:
    """Configures the requests-cache session"""
    cache_path = platformdirs.user_cache_path("idapro-plugin-list")
    cache_path.mkdir(exist_ok=True, parents=True)
    cache_file = cache_path.joinpath("http_cache.sqlite3")
    return CachedSession(backend=SQLiteCache(cache_file))


def get_plugin_projects_from_pypi(session: CachedSession) -> dict[str, int]:
    response = session.get(
        "https://pypi.org/simple",
        headers={"Accept": "application/vnd.pypi.simple.v1+json"},
        refresh=True,
    )
    return {
        name: p["_last-serial"]
        for p in response.json()["projects"]
        if ((name := p["name"]).startswith(("idapro-plugin-", "idapro_plugin_"))
            or name.endswith(("-idapro-plugin", "_idapro_plugin"))
            or name.endswith(("-ida-plugin", "_ida_plugin"))
            or name in ADDITIONAL_PROJECTS)
    }


class PluginInfo(TypedDict):
    """Relevant information about a plugin to generate the summary."""

    name: str
    summary: str
    last_release: str


def iter_plugins() -> Iterator[PluginInfo]:
    session = get_session()
    projects_by_serial = get_plugin_projects_from_pypi(session)

    with Progress(transient=True) as progress:
        task = progress.add_task("Finding plugins...", total=len(projects_by_serial))
        for name, last_serial in projects_by_serial.items():
            response = get_project_with_refresh(session, name, last_serial)
            if response.status_code == 404:
                # Some packages, like pytest-azurepipelines42, are included in https://pypi.org/simple
                # but return 404 on the JSON API. Skip.
                progress.advance(task)
                continue
            response.raise_for_status()
            info = response.json()["info"]

            def version_sort_key(version_string: str) -> Any:
                """
                Return the sort key for the given version string
                returned by the API.
                """
                try:
                    return packaging.version.parse(version_string)
                except packaging.version.InvalidVersion:
                    # Use a hard-coded pre-release version.
                    return packaging.version.Version("0.0.0alpha")

            last_release = "N/A"
            last_release_date = "N/A"
            releases = response.json()["releases"]
            for release in sorted(releases, key=version_sort_key, reverse=True):
                if releases[release]:
                    release_date = datetime.date.fromisoformat(
                        releases[release][-1]["upload_time_iso_8601"].split("T")[0]
                    )
                    last_release = release
                    last_release_date = release_date.strftime("%b %d, %Y")
                    break
            yield {
                "name": info["name"],
                "summary": info["summary"].replace("\n", "").strip(),
                "last_release": last_release,
                "last_release_date": last_release_date,
            }
            progress.advance(task)


def main() -> None:
    t = rich.table.Table()
    t.add_column("Name", style="bold")
    t.add_column("Last Release", style="bold")
    t.add_column("Summary", style="bold")

    for plugin in iter_plugins():
        t.add_row(
            plugin["name"],
            plugin["last_release"] + " on " + plugin["last_release_date"],
            plugin["summary"],
        )

    if t.row_count:
        rich.print(t)
    else:
        rich.print("No plugins found.")


if __name__ == "__main__":
    main()
