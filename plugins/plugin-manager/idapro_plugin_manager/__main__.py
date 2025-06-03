from __future__ import annotations

import os
import re
import sys
import argparse
import datetime
import subprocess
from typing import Any
from pathlib import Path
from dataclasses import dataclass
from collections.abc import Iterator

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
from rich.markdown import Markdown
from rich.progress import Progress
from requests_cache import SQLiteCache, CachedSession, CachedResponse, OriginalResponse

# manually registered plugins, which requires a new release of ippm to update.
ADDITIONAL_PROJECTS: set[str] = set()
IGNORED_PROJECTS: set[str] = {
    "idapro-plugin-manager",  # this project, which isn't a plugin, but has the prefix.
}

# Bootstrap plugin content that gets installed to $IDADIR/plugins/
BOOTSTRAP_PLUGIN_CONTENT = """import idaapi

import idapro_plugin_manager


class loader_plugin_t(idaapi.plugin_t):
    # don't use PLUGIN_FIX because we want plugins to be re-loaded at various lifecycle points, not just at startup.
    flags = idaapi.PLUGIN_MULTI | idaapi.PLUGIN_HIDE
    comment = "Plugin used to load other plugins"
    help = "Plugin used to load other plugins"
    wanted_name = "IDA Pro Plugin Manager Loader"
    wanted_hotkey = ""

    def init(self):
        idapro_plugin_manager.install()


def PLUGIN_ENTRY():
    return loader_plugin_t()
"""


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


def is_valid_package_spec(package_spec: str) -> bool:
    """Validate that a package specification is safe and well-formed."""
    # Allow only alphanumeric characters, hyphens, underscores, dots, and version specs
    # This prevents shell injection and ensures we only get valid package names
    pattern = r"^[a-zA-Z0-9._-]+(?:==|>=|<=|>|<|!=|~=)?[a-zA-Z0-9._-]*$"
    return bool(re.match(pattern, package_spec))


def run_pip_command(args: list[str]) -> tuple[bool, str]:
    """Run a pip command safely and return success status and output."""
    try:
        result = subprocess.run(
            # this won't work if we execute within IDA
            # I wonder if we can invoke pip as a module in the curren interpreter?
            [sys.executable, "-m", "pip"] + args,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,  # 5 minute timeout
        )
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "Command timed out after 5 minutes"


def get_installed_ida_plugins() -> list[str]:
    """Get list of currently installed IDA Pro plugins using entry points mechanism."""
    installed_plugins = []

    plugins = list(importlib_metadata.entry_points(group="idapro.plugins"))

    for plugin in plugins:
        if plugin.dist:
            installed_plugins.append(plugin.dist.name)

    return list(set(installed_plugins))


def handle_list_command(args: argparse.Namespace) -> int:
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

    return 0


def handle_show_command(args: argparse.Namespace) -> int:
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
            if value := info.get(key):
                table.add_row(display, value)

        if project_urls := info.get("project_urls"):
            for key, url in project_urls.items():
                table.add_row(f"Project URL ({key})", url)

        if "classifiers" in info and info["classifiers"]:
            table.add_row("Classifiers", "\n".join(info["classifiers"]))

        if "requires_dist" in info and info["requires_dist"]:
            table.add_row("Dependencies", "\n".join(info["requires_dist"]))

        downloads = info.get("downloads", {})
        if downloads and downloads.get("last_day", -1) != -1:
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
                        e["upload_time_iso_8601"] for e in release_files_list if "upload_time_iso_8601" in e
                    ]
                    if not upload_times:
                        upload_date = None
                    else:
                        earliest_upload_time_iso = min(upload_times)
                        upload_date = datetime.datetime.fromisoformat(earliest_upload_time_iso.replace("Z", "+00:00"))
                    all_files_yanked = all(e.get("yanked", False) for e in release_files_list)

                if upload_date:
                    version_history_data.append((upload_date, version_s, all_files_yanked))

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
        return 0

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            rich.print(f"[bold red]Error: Plugin '{plugin_name}' not found on PyPI.[/]")
            return 0
        else:
            rich.print(
                f"[bold red]Error fetching plugin details: HTTP {e.response.status_code} - {e.response.reason}[/]"
            )
            return 0


def handle_install_command(args: argparse.Namespace) -> int:
    package_spec = args.package_spec

    if not is_valid_package_spec(package_spec):
        rich.print(f"[bold red]Error: Invalid package specification '{package_spec}'[/]")
        rich.print("Package name must contain only alphanumeric characters, hyphens, underscores, and dots.")
        rich.print("Version specifications like '==1.0.0' are allowed.")
        return -1

    rich.print(f"Installing plugin: [cyan]{package_spec}[/]")

    success, output = run_pip_command(["install", package_spec])

    if success:
        rich.print(f"[green]Successfully installed {package_spec}[/]")
        if output.strip():
            for line in output.strip().split("\n"):
                if line.strip():
                    rich.print(f"  {line}")
    else:
        rich.print(f"[bold red]Failed to install {package_spec}[/]")
        rich.print("Error output:")
        for line in output.strip().split("\n"):
            if line.strip():
                rich.print(f"  {line}")
        return -1

    return 0


def handle_remove_command(args: argparse.Namespace) -> int:
    package_name = args.package_name

    if not is_valid_package_spec(package_name):
        rich.print(f"[bold red]Error: Invalid package name '{package_name}'[/]")
        rich.print("Package name must contain only alphanumeric characters, hyphens, underscores, and dots.")
        return -1

    try:
        importlib_metadata.distribution(package_name)
    except importlib_metadata.PackageNotFoundError:
        rich.print(f"[yellow]Package '{package_name}' is not installed[/]")
        return 0

    rich.print(f"Removing plugin: [cyan]{package_name}[/]")

    success, output = run_pip_command(["uninstall", package_name, "--yes"])

    if success:
        rich.print(f"[green]Successfully removed {package_name}[/]")
    else:
        rich.print(f"[bold red]Failed to remove {package_name}[/]")
        rich.print("Error output:")
        for line in output.strip().split("\n"):
            if line.strip():
                rich.print(f"  {line}")
        return -1

    return 0


def handle_update_command(args: argparse.Namespace) -> int:
    package_name = args.package_name

    if not is_valid_package_spec(package_name):
        rich.print(f"[bold red]Error: Invalid package name '{package_name}'[/]")
        rich.print("Package name must contain only alphanumeric characters, hyphens, underscores, and dots.")
        return -1

    try:
        importlib_metadata.distribution(package_name)
    except importlib_metadata.PackageNotFoundError:
        rich.print(f"[yellow]Package '{package_name}' is not installed[/]")
        return 0

    rich.print(f"Updating plugin: [cyan]{package_name}[/]")

    success, output = run_pip_command(["install", "--upgrade", package_name])

    if success:
        # Check if there was actually an update or if it was already up to date
        if "already satisfied" in output.lower() or "already up-to-date" in output.lower():
            rich.print(f"[green]{package_name} is already up to date[/]")
        else:
            rich.print(f"[green]Successfully updated {package_name}[/]")
        # Show brief output
        if output.strip():
            for line in output.strip().split("\n")[-3:]:  # Show last 3 lines
                if line.strip():
                    rich.print(f"  {line}")
    else:
        rich.print(f"[bold red]Failed to update {package_name}[/]")
        rich.print("Error output:")
        for line in output.strip().split("\n"):
            if line.strip():
                rich.print(f"  {line}")
        return -1

    return 0


def handle_update_all_command(args: argparse.Namespace) -> int:
    rich.print("Finding installed IDA Pro plugins...")

    installed_plugins = get_installed_ida_plugins()

    if not installed_plugins:
        rich.print("[yellow]No IDA Pro plugins are currently installed[/]")
        return 0

    rich.print(f"Found {len(installed_plugins)} installed IDA Pro plugin(s):")
    for plugin in installed_plugins:
        rich.print(f"  - [cyan]{plugin}[/]")

    rich.print("\nChecking for updates...")

    plugins_to_update = []

    for plugin in installed_plugins:
        dist = importlib_metadata.distribution(plugin)
        installed_version = dist.version

        session = get_session()
        response = session.get(f"https://pypi.org/pypi/{plugin}/json")
        if response.status_code == 404:
            rich.print(f"  [yellow]{plugin}: Not found on PyPI, skipping[/]")
            continue
        response.raise_for_status()
        data = response.json()
        latest_version = data["info"]["version"]

        try:
            installed_ver = packaging.version.parse(installed_version)
            latest_ver = packaging.version.parse(latest_version)
            if latest_ver > installed_ver:
                plugins_to_update.append(plugin)
                rich.print(f"  [cyan]{plugin}[/]: {installed_version} → {latest_version}")
            else:
                rich.print(f"  [green]{plugin}[/]: {installed_version} (up to date)")
        except packaging.version.InvalidVersion:
            plugins_to_update.append(plugin)
            rich.print(f"  [yellow]{plugin}[/]: version comparison failed, will attempt update")

    if not plugins_to_update:
        rich.print("\n[green]All plugins are up to date![/]")
        return 0

    rich.print(f"\nUpdating {len(plugins_to_update)} plugin(s)...")

    failed_updates = []
    for plugin in plugins_to_update:
        rich.print(f"Updating [cyan]{plugin}[/]...")

        success, output = run_pip_command(["install", "--upgrade", plugin])

        if success:
            rich.print(f"  [green]Successfully updated {plugin}[/]")
        else:
            rich.print(f"  [bold red]Failed to update {plugin}[/]")
            failed_updates.append(plugin)
            for line in output.strip().split("\n"):
                if line.strip():
                    rich.print(f"    {line}")

    if failed_updates:
        rich.print(f"\n[bold red]Failed to update {len(failed_updates)} plugin(s):[/]")
        for plugin in failed_updates:
            rich.print(f"  - {plugin}")
        return -1
    else:
        rich.print("\n[green]All plugins updated successfully![/]")
        return 0


def get_idausr_directory() -> Path:
    if sys.platform == "win32":
        # Windows: %APPDATA%/Hex-Rays/IDA Pro
        appdata = os.environ.get("APPDATA")
        if idausr := appdata:
            idausr = Path(idausr) / "Hex-Rays" / "IDA Pro"
        else:
            raise ValueError("failed to find %APPDATA% environment variable")
    else:
        # Linux and Mac: $HOME/.idapro
        if home := os.environ.get("HOME"):
            idausr = Path(home) / ".idapro"
        else:
            raise ValueError("failed to find $HOME environment variable")

    if not idausr or not idausr.exists():
        raise ValueError(f"$IDAUSR directory does not exist: {idausr}")

    return idausr


def handle_register_command(args: argparse.Namespace) -> int:
    try:
        idausr = get_idausr_directory()
    except ValueError as e:
        rich.print(f"[bold red]Error: Could not find the $IDAUSR directory: {e}[/]")
        return -1

    plugins_dir = idausr / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)

    bootstrap_file = plugins_dir / "load-idapro-plugin-manager.py"

    if bootstrap_file.exists():
        existing_content = bootstrap_file.read_text()
        if existing_content.strip() == BOOTSTRAP_PLUGIN_CONTENT.strip():
            rich.print("[green]Bootstrap plugin is already installed and up to date.[/]")
            return 0

        else:
            rich.print("[bold red]Error: Bootstrap plugin file already exists with different content.[/]")
            rich.print(f"File location: {bootstrap_file}")
            rich.print("The existing file may be from a different version or manually modified.")
            rich.print("Please backup and remove the existing file if you want to proceed.")
            return -1

    try:
        bootstrap_file.write_text(BOOTSTRAP_PLUGIN_CONTENT)
        rich.print(f"[green]Successfully installed bootstrap plugin to {bootstrap_file}[/]")
        rich.print("The IDA Pro Plugin Manager is now registered with IDA Pro.")
        return 0
    except PermissionError:
        rich.print("[bold red]Error: Permission denied writing to IDA plugins directory.[/]")
        return -1


def handle_version_command(args: argparse.Namespace) -> int:
    version = importlib_metadata.version("idapro-plugin-manager")
    rich.print(f"ippm version {version}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="IDA Pro Plugin Manager (ippm). Manages IDA Pro plugins found on PyPI."
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # version command
    version_parser = subparsers.add_parser("version", help="Show program's version number and exit.")
    version_parser.set_defaults(func=handle_version_command)

    # register command
    register_parser = subparsers.add_parser("register", help="Register the plugin manager with IDA Pro.")
    register_parser.set_defaults(func=handle_register_command)

    # install command
    install_parser = subparsers.add_parser("install", help="Install an IDA Pro plugin from PyPI.")
    install_parser.add_argument(
        "package_spec",
        metavar="PACKAGE",
        help="Package name or package name with version (e.g., 'plugin-name' or 'plugin-name==1.0.0')",
    )
    install_parser.set_defaults(func=handle_install_command)

    # remove command
    remove_parser = subparsers.add_parser("remove", help="Remove an installed IDA Pro plugin.")
    remove_parser.add_argument("package_name", metavar="PACKAGE_NAME", help="The name of the plugin to remove.")
    remove_parser.set_defaults(func=handle_remove_command)

    # update command
    update_parser = subparsers.add_parser("update", help="Update a specific IDA Pro plugin to its latest version.")
    update_parser.add_argument("package_name", metavar="PACKAGE_NAME", help="The name of the plugin to update.")
    update_parser.set_defaults(func=handle_update_command)

    # update-all command
    update_all_parser = subparsers.add_parser(
        "update-all", help="Update all outdated IDA Pro plugins to their latest versions."
    )
    update_all_parser.set_defaults(func=handle_update_all_command)

    list_parser = subparsers.add_parser("list", help="List available IDA Pro plugins on PyPI.")
    list_parser.set_defaults(func=handle_list_command)

    show_parser = subparsers.add_parser("show", help="Show detailed information for a specific plugin on PyPI.")
    show_parser.add_argument("plugin_name", metavar="PLUGIN_NAME", help="The name of the plugin on PyPI.")
    show_parser.set_defaults(func=handle_show_command)

    args = parser.parse_args()
    if hasattr(args, "func"):
        return args.func(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
