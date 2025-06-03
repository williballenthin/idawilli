from __future__ import annotations

import sys
import argparse
import datetime
from typing import Any
from collections.abc import Iterator
from dataclasses import dataclass

if sys.version_info < (3, 10):
    # once we drop support for Python 3.9,
    # remove this and the dependency on `importlib_metadata`.
    import importlib_metadata
else:
    import importlib.metadata as importlib_metadata


import rich
import rich.table
import platformdirs
import packaging.version
import requests.exceptions
from rich.progress import Progress
from rich.markdown import Markdown
from requests_cache import SQLiteCache, CachedSession, CachedResponse, OriginalResponse

# manually registered plugins, which requires a new release of ippm to update.
ADDITIONAL_PROJECTS: set[str] = set()
IGNORED_PROJECTS: set[str] = {
    "idapro-plugin-manager",  # this project, which isn't a plugin, but has the prefix.
}


def get_session() -> CachedSession:
    cache_path = platformdirs.user_cache_path("idapro-plugin-manager")
    cache_path.mkdir(exist_ok=True, parents=True)
    cache_file = cache_path.joinpath("ippm.sqlite3")
    return CachedSession(backend=SQLiteCache(cache_file))


def get_project_with_refresh(session: CachedSession, name: str, last_serial: int) -> OriginalResponse | CachedResponse:
    """Get a http cached pypi project, force refresh in case of last serial mismatch."""
    response = session.get(f"https://pypi.org/pypi/{name}/json")
    if int(response.headers.get("X-PyPI-Last-Serial", -1)) != last_serial:
        response = session.get(f"https://pypi.org/pypi/{name}/json", refresh=True)
    return response


def get_plugin_projects_from_pypi(session: CachedSession) -> dict[str, int]:
    """Fetches projects from PyPI simple API, filtering for IDA Pro plugins."""
    response = session.get(
        "https://pypi.org/simple",
        headers={"Accept": "application/vnd.pypi.simple.v1+json"},
        refresh=True,
    )
    response.raise_for_status()
    return {
        name: p["_last-serial"]
        for p in response.json()["projects"]
        if (
            (name := p["name"]).startswith(("idapro-plugin-", "idapro_plugin_"))
            or name.endswith(("-idapro-plugin", "_idapro_plugin"))
            or name.endswith(("-ida-plugin", "_ida_plugin"))
            or name in ADDITIONAL_PROJECTS
        )
        and name not in IGNORED_PROJECTS
    }


@dataclass
class PluginInfo:
    name: str
    summary: str
    last_release: str
    last_release_date: str
    installed_version: str | None
    is_outdated: bool | None


def iter_plugins() -> Iterator[PluginInfo]:
    """Iterates over discovered IDA Pro plugins on PyPI, yielding their info."""
    session = get_session()
    projects_by_serial = get_plugin_projects_from_pypi(session)

    with Progress(transient=True) as progress:
        task = progress.add_task("Finding plugins...", total=len(projects_by_serial))
        for name, last_serial in projects_by_serial.items():
            try:
                response = get_project_with_refresh(session, name, last_serial)
                if response.status_code == 404:
                    progress.console.print(f"Skipping {name}: Not found on JSON API (404)", style="yellow")
                    progress.advance(task)
                    continue
                response.raise_for_status()
                data = response.json()
                info = data["info"]

                def version_sort_key(version_string: str) -> Any:
                    try:
                        return packaging.version.parse(version_string)
                    except packaging.version.InvalidVersion:
                        # Use a hard-coded pre-release version for invalid ones
                        return packaging.version.Version("0.0.0alpha0")

                last_release_str = "N/A"
                last_release_date_str = "N/A"
                releases = data.get("releases", {})

                for version_str in sorted(releases.keys(), key=version_sort_key, reverse=True):
                    release_entries = releases.get(version_str, [])
                    if not release_entries:
                        # no files for this version
                        continue

                    non_yanked_entries = [e for e in release_entries if not e.get("yanked", False)]

                    if non_yanked_entries:
                        upload_time_iso = max(e["upload_time_iso_8601"] for e in non_yanked_entries)
                        release_date = datetime.date.fromisoformat(upload_time_iso.split("T")[0])
                        last_release_str = version_str
                        last_release_date_str = release_date.strftime("%b %d, %Y")
                        break

                    elif not info.get("yanked", False) and all(e.get("yanked", False) for e in release_entries):
                        # All files for this version are yanked,
                        # but the version itself is not marked yanked at top level.
                        upload_time_iso = max(e["upload_time_iso_8601"] for e in release_entries)
                        release_date = datetime.date.fromisoformat(upload_time_iso.split("T")[0])
                        last_release_str = version_str
                        last_release_date_str = release_date.strftime("%b %d, %Y (all files yanked)")
                        break

                installed_version_str: str | None = None
                is_outdated: bool | None = None
                try:
                    # Use the original PyPI name for checking installation
                    dist = importlib_metadata.distribution(info["name"])
                    installed_version_str = dist.version
                    if last_release_str != "N/A" and installed_version_str:
                        try:
                            pypi_ver = packaging.version.parse(last_release_str)
                            installed_ver = packaging.version.parse(installed_version_str)
                            if pypi_ver > installed_ver:
                                is_outdated = True
                            else:
                                is_outdated = False  # Up-to-date or same version
                        except packaging.version.InvalidVersion:
                            # If either version string is invalid, can't reliably compare
                            pass  # is_outdated remains None
                except importlib_metadata.PackageNotFoundError:
                    pass  # Not installed, is_outdated remains None

                yield PluginInfo(
                    name=info["name"],
                    summary=info.get("summary", "N/A").replace("\n", " ").strip(),
                    last_release=last_release_str,
                    last_release_date=last_release_date_str,
                    installed_version=installed_version_str,
                    is_outdated=is_outdated,
                )

            except requests.exceptions.HTTPError as e:
                progress.console.print(
                    f"Error fetching {name}: HTTP {e.response.status_code} - {e.response.reason}", style="red"
                )
            finally:
                progress.advance(task)


def handle_list_command(args: argparse.Namespace) -> None:
    table = rich.table.Table(title="Available IDA Pro Plugins on PyPI")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Last Release", style="magenta")
    table.add_column("Summary", style="green")

    plugins_found = False
    for plugin_info in iter_plugins():
        plugins_found = True

        plugin_name_display = plugin_info.name
        installed_version = plugin_info.installed_version
        is_outdated = plugin_info.is_outdated

        if installed_version is not None:
            if is_outdated is True:
                plugin_name_display += (
                    f" [grey30](installed: {installed_version}, latest: {plugin_info.last_release})[/]"
                )
            elif is_outdated is False:  # Explicitly up-to-date or same version
                plugin_name_display += " [grey30](installed)[/]"
            else:  # is_outdated is None (e.g., PyPI version N/A or version parse error)
                plugin_name_display += f" [grey30](installed: {installed_version})[/]"

        table.add_row(
            plugin_name_display,
            f"{plugin_info.last_release} ({plugin_info.last_release_date})",
            plugin_info.summary,
        )

    if plugins_found:
        rich.print(table)
    else:
        rich.print("No IDA Pro plugins found on PyPI matching the criteria.")


def handle_show_command(args: argparse.Namespace) -> None:
    plugin_name = args.plugin_name
    session = get_session()
    try:
        response = session.get(f"https://pypi.org/pypi/{plugin_name}/json")
        response.raise_for_status()
        data = response.json()
        info = data["info"]

        table = rich.table.Table(show_header=False)
        table.add_column("Field", style="bold blue")
        table.add_column("Value")

        table.add_row("Name", f"[yellow]{info.get('name')}[/yellow]")
        table.add_row("Version", info.get("version"))
        table.add_row("Summary", info.get("summary") or "N/A")
        table.add_row("Author", info.get("author_email") or info.get("author") or "N/A")
        table.add_row("License", info.get("license_expression") or info.get("license") or "N/A")
        if info.get("requires_python"):
            table.add_row("Requires Python", info.get("requires_python") or "N/A")
        if info.get("keywords"):
            table.add_row("Keywords", info.get("keywords") or "N/A")

        url_fields = [
            ("Home Page", "home_page"),
            ("Package URL", "package_url"),
            ("Project URL", "project_url"),
            ("Release URL", "release_url"),
            ("Docs URL", "docs_url"),
            ("Bug Tracker URL", "bugtrack_url"),
            ("Download URL", "download_url"),
            ("Platform", "platform"),
        ]
        for display, key in url_fields:
            if (value := info.get(key)):
                table.add_row(display, value)

        if (project_urls := info.get("project_urls")):
            for key, url in project_urls.items():
                table.add_row(f"Project URL ({key})", url)

        if "classifiers" in info and info["classifiers"]:
            table.add_row("Classifiers", "\n".join(info["classifiers"]))

        if "requires_dist" in info and info["requires_dist"]:
            table.add_row("Dependencies", "\n".join(info["requires_dist"]))

        downloads = info.get("downloads", {})
        if downloads and downloads.get("last_day", -1) != -1 :
            table.add_row("Downloads (Day)", str(downloads.get("last_day")))
            table.add_row("Downloads (Week)", str(downloads.get("last_week")))
            table.add_row("Downloads (Month)", str(downloads.get("last_month")))

        if info.get("yanked", False):
            table.add_row("Yanked", info.get("yanked_reason", "true"))
        releases = data.get("releases", {})

        if releases:
            version_history_lines = []
            version_history_data = []
            for version_s, release_files_list in releases.items():
                if not release_files_list:
                    upload_date = None
                    all_files_yanked = False
                else:
                    upload_times = [
                        e["upload_time_iso_8601"]
                        for e in release_files_list
                        if "upload_time_iso_8601" in e
                    ]
                    if not upload_times:
                        upload_date = None
                    else:
                        earliest_upload_time_iso = min(upload_times)
                        upload_date = datetime.datetime.fromisoformat(
                            earliest_upload_time_iso.replace("Z", "+00:00")
                        )
                    all_files_yanked = all(e.get("yanked", False) for e in release_files_list)

                if upload_date:
                    version_history_data.append(
                        (upload_date, version_s, all_files_yanked)
                    )
            
            version_history_data.sort(key=lambda x: x[0], reverse=True)

            if version_history_data:
                for date_obj, ver_str, is_yanked in version_history_data:
                    date_display = date_obj.strftime("%b %d, %Y")
                    status = " [yellow](yanked)[/yellow]" if is_yanked else ""
                    version_history_lines.append(f"[cyan]{ver_str:<15}[/] [magenta]{date_display:<15}[/] {status}")
                table.add_row("Version History", "\n".join(version_history_lines))

        description = info.get("description", "")
        if description:
            description_content_type = info.get("description_content_type", "")
            if description_content_type == "text/markdown":
                table.add_row(f"Description ({description_content_type})", Markdown(description))
            else:
                table.add_row(f"Description ({description_content_type})", description)

        rich.print(table)

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            rich.print(f"[bold red]Error: Plugin '{plugin_name}' not found on PyPI.[/]")
        else:
            rich.print(
                f"[bold red]Error fetching plugin details: HTTP {e.response.status_code} - {e.response.reason}[/]"
            )


def handle_version_command(args: argparse.Namespace) -> None:
    version = importlib_metadata.version("idapro-plugin-manager")
    rich.print(f"ippm version {version}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="IDA Pro Plugin Manager (ippm). Manages IDA Pro plugins found on PyPI."
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # version command
    version_parser = subparsers.add_parser("version", help="Show program's version number and exit.")
    version_parser.set_defaults(func=handle_version_command)

    list_parser = subparsers.add_parser("list", help="List available IDA Pro plugins on PyPI.")
    list_parser.set_defaults(func=handle_list_command)

    show_parser = subparsers.add_parser("show", help="Show detailed information for a specific plugin on PyPI.")
    show_parser.add_argument("plugin_name", metavar="PLUGIN_NAME", help="The name of the plugin on PyPI.")
    show_parser.set_defaults(func=handle_show_command)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
