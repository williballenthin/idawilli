#!/usr/bin/env python3
"""
Plugin Migration Script

Replaces copybara for migrating 3rd-party IDA plugins.
Each plugin is migrated to its own directory to avoid conflicts.

Usage:
    python migrate_plugins.py [plugin_name]
    python migrate_plugins.py  # migrates all plugins
"""

import shutil
import fnmatch
import tempfile
import subprocess
from typing import List, Optional
from pathlib import Path
from dataclasses import field, dataclass

from rich import print

# Global pyproject.toml templates
HRDEVHELPER_PYPROJECT = """[project]
name = "3p-HRDevHelper-ida-plugin"
authors = [
  {name = "Dennis Elser"},
]
maintainers = [
  {name = "Willi Ballenthin", email = "willi.ballenthin@gmail.com"},
]
description = "A helpful tool for debugging and developing your own Hexrays plugins and scripts"
version = "2025.6.6"
readme = "README.md"
license-files = [ "LICENSE" ]
requires-python = ">=3.9"
dependencies = []

[project.urls]
source = "https://github.com/patois/HRDevHelper"
repository = "https://github.com/patois/HRDevHelper"
plugin-source = "https://github.com/williballenthin/idawilli/tree/master/plugins/plugin-manager/3p-plugins/"

[project.entry-points.'idapro.plugins']
idapython = "hrdh.hrdevhelper"

[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"
"""

DEREFERENCING_PYPROJECT = """[project]
name = "3p-deREFerencing-ida-plugin"
authors = [
  {name = "Daniel Garcia", email = "danigargu@gmail.com"},
]
maintainers = [
  {name = "Willi Ballenthin", email = "willi.ballenthin@gmail.com"},
]
description = "IDA Pro plugin that implements more user-friendly register and stack views"
version = "2025.6.10"
readme = "README.md"
license-files = [ "LICENSE" ]
requires-python = ">=3.9"
dependencies = []

[project.urls]
source = "https://github.com/danigargu/deREferencing"
repository = "https://github.com/danigargu/deREferencing"
plugin-source = "https://github.com/williballenthin/idawilli/tree/master/plugins/plugin-manager/3p-plugins/"

[project.entry-points.'idapro.plugins']
idapython = "dereferencing.plugin"

[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"
"""

IDA_TERMINAL_PYPROJECT = """[project]
name = "3p-terminal-ida-plugin"
authors = [
  {name = "Hex-Rays SA"},
]
maintainers = [
  {name = "Willi Ballenthin", email = "willi.ballenthin@gmail.com"},
]
description = "A lightweight terminal integration for IDA Pro that lets you open a fully functional terminal within the IDA GUI"
version = "2025.6.12"
readme = "README.md"
license-files = [ "LICENSE" ]
requires-python = ">=3.9"
dependencies = []

[project.urls]
source = "https://github.com/HexRaysSA/ida-terminal-plugin"
repository = "https://github.com/HexRaysSA/ida-terminal-plugin"
plugin-source = "https://github.com/williballenthin/idawilli/tree/master/plugins/plugin-manager/3p-plugins/"

[project.entry-points.'idapro.plugins']
idapython = "ida_terminal_module.plugin"

[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"
"""

IDA_TERMINAL_INIT = '''"""IDA Terminal Plugin Module

A lightweight terminal integration for IDA Pro.
"""'''

LAZYIDA_PYPROJECT = """[project]
name = "3p-LazyIDA-ida-plugin"
authors = [
  {name = "Lays"},
]
maintainers = [
  {name = "Willi Ballenthin", email = "willi.ballenthin@gmail.com"},
]
description = "Make your IDA Lazy! A collection of useful utilities for IDA Pro analysis"
version = "2025.6.12"
readme = "README.md"
license-files = [ "LICENSE" ]
requires-python = ">=3.9"
dependencies = []

[project.urls]
source = "https://github.com/L4ys/LazyIDA"
repository = "https://github.com/L4ys/LazyIDA"
plugin-source = "https://github.com/williballenthin/idawilli/tree/master/plugins/plugin-manager/3p-plugins/"

[project.entry-points.'idapro.plugins']
idapython = "lazyida.plugin"

[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"
"""

SWIFTSTRINGINSPECTOR_PYPROJECT = """[project]
name = "3p-SwiftStringInspector-ida-plugin"
authors = [
  {name = "Keowu"},
]
maintainers = [
  {name = "Willi Ballenthin", email = "willi.ballenthin@gmail.com"},
]
description = "A simple plugin for working with Swift Strings, optimized Swift Strings, and Swift Arrays during the reverse engineering of iOS binaries in Hex-Rays IDA"
version = "2025.6.12"
readme = "README.md"
license-files = [ "LICENSE" ]
requires-python = ">=3.9"
dependencies = []

[project.urls]
source = "https://github.com/keowu/swiftstringinspector"
repository = "https://github.com/keowu/swiftstringinspector"
plugin-source = "https://github.com/williballenthin/idawilli/tree/master/plugins/plugin-manager/3p-plugins/"

[project.entry-points.'idapro.plugins']
idapython = "swiftstringinspector.plugin"

[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"
"""

XREFER_PYPROJECT = """[project]
name = "3p-xrefer-ida-plugin"
authors = [
  {name = "m-umairx"},
]
maintainers = [
  {name = "Willi Ballenthin", email = "willi.ballenthin@gmail.com"},
]
description = "FLARE Team's Binary Navigator. XRefer is a Python-based plugin for IDA Pro that provides a custom navigation interface, analyzes execution paths, clusters functions, and highlights downstream behaviors. It can incorporate external data and integrates with LLMs for code descriptions."
version = "2025.6.12"
readme = "README.md"
license-files = [ "LICENSE" ]
requires-python = ">=3.9"
dependencies = [
  "flare_capa",
  "networkx",
  "Requests",
  "tabulate",
  "asciinet",
  "bs4",
  "langchain",
  "langchain_google_genai",
  "langchain_openai",
  "tenacity",
  "python-statemachine",
  "asciinet"
]

[project.urls]
source = "https://github.com/mandiant/xrefer"
repository = "https://github.com/mandiant/xrefer"
plugin-source = "https://github.com/williballenthin/idawilli/tree/master/plugins/plugin-manager/3p-plugins/"

[project.entry-points.'idapro.plugins']
idapython = "xrefer.entry"

[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"
"""

XREFER_ENTRY = """
from xrefer.plugin import XReferPlugin

def PLUGIN_ENTRY():
    return XReferPlugin()
"""

HEXRAYSPYTOOLS_PYPROJECT = """[project]
name = "3p-HexRaysPyTools-ida-plugin"
authors = [
  {name = "igogo-x86"},
]
maintainers = [
  {name = "Willi Ballenthin", email = "willi.ballenthin@gmail.com"},
]
description = "IDA Pro plugin which improves work with HexRays decompiler and helps in process of reconstruction structures and classes"
version = "2025.6.13"
readme = "readme.md"
requires-python = ">=3.9"
dependencies = []

[project.urls]
source = "https://github.com/igogo-x86/HexRaysPyTools"
repository = "https://github.com/igogo-x86/HexRaysPyTools"
plugin-source = "https://github.com/williballenthin/idawilli/tree/master/plugins/plugin-manager/3p-plugins/"

[project.entry-points.'idapro.plugins']
idapython = "HexRaysPyTools.plugin"

[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"
"""

IDAFUZZY_PYPROJECT = """[project]
name = "3p-IDAFuzzy-ida-plugin"
authors = [
  {name = "Ga-ryo"},
]
maintainers = [
  {name = "Willi Ballenthin", email = "willi.ballenthin@gmail.com"},
]
description = "Fuzzy searching tool for IDA Pro"
version = "2025.6.13"
readme = "README.md"
license-files = [ "LICENSE" ]
requires-python = ">=3.9"
dependencies = [
  "fuzzywuzzy[speedup]",
]

[project.urls]
source = "https://github.com/Ga-ryo/IDAFuzzy"
repository = "https://github.com/Ga-ryo/IDAFuzzy"
plugin-source = "https://github.com/williballenthin/idawilli/tree/master/plugins/plugin-manager/3p-plugins/"

[project.entry-points.'idapro.plugins']
idapython = "idafuzzy.plugin"

[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"
"""

HEXLIGHT_PYPROJECT = """[project]
name = "3p-hexlight-ida-plugin"
authors = [
  {name = "Milan Bohacek", email = "milan.bohacek+hexlight@gmail.com"},
]
maintainers = [
  {name = "Willi Ballenthin", email = "willi.ballenthin@gmail.com"},
]
description = "Highlighting plugin for Hex-Rays Decompiler - highlights matching braces and allows navigation with 'B' key"
version = "2025.6.13"
requires-python = ">=3.9"
dependencies = []

[project.urls]
source = "https://github.com/stevemk14ebr/RETools"
repository = "https://github.com/stevemk14ebr/RETools"
plugin-source = "https://github.com/williballenthin/idawilli/tree/master/plugins/plugin-manager/3p-plugins/"

[project.entry-points.'idapro.plugins']
idapython = "hexlight.plugin"

[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"
"""

STRING_FROM_SELECTION_PYPROJECT = """[project]
name = "3p-string-from-selection-ida-plugin"
authors = [
  {name = "stevemk14ebr"},
]
maintainers = [
  {name = "Willi Ballenthin", email = "willi.ballenthin@gmail.com"},
]
description = "Define a string from selection, useful for non-null terminated strings"
version = "2025.6.13"
requires-python = ">=3.9"
dependencies = []

[project.urls]
source = "https://github.com/stevemk14ebr/RETools"
repository = "https://github.com/stevemk14ebr/RETools"
plugin-source = "https://github.com/williballenthin/idawilli/tree/master/plugins/plugin-manager/3p-plugins/"

[project.entry-points.'idapro.plugins']
idapython = "string_from_selection.plugin"

[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"
"""


@dataclass
class PluginConfig:
    """Configuration for a single plugin migration."""

    name: str
    repo_url: str
    commit: str
    include_files: List[str]
    exclude_files: List[str] = field(default_factory=list)
    transformations: List = field(default_factory=list)


class FileTransformation:
    """Base class for file transformations.

    All transformation classes should implement the apply() method:
        def apply(self, work_dir: Path) -> None:
            # Apply transformation to files in work_dir
    """

    def apply(self, work_dir: Path) -> None:
        """Apply the transformation to files in the working directory."""
        raise NotImplementedError("Subclasses must implement apply()")


@dataclass
class MoveFile(FileTransformation):
    """Move/rename a file."""

    src: str
    dst: str

    def apply(self, work_dir: Path) -> None:
        src_path = work_dir / self.src
        dst_path = work_dir / self.dst

        if src_path.exists():
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src_path), str(dst_path))
            print(f"  [cyan]Moved[/] {self.src} [cyan]->[/] {self.dst}")
        else:
            print(f"  [red]Failed to move[/] {self.src} (does not exist)")


@dataclass
class ReplaceText(FileTransformation):
    """Replace text in a file."""

    file_pattern: str
    old_text: str
    new_text: str

    def apply(self, work_dir: Path) -> None:
        for file_path in work_dir.rglob("*"):
            if file_path.is_file() and fnmatch.fnmatch(file_path.name, self.file_pattern):
                try:
                    content = file_path.read_text(encoding="utf-8")
                    if self.old_text in content:
                        new_content = content.replace(self.old_text, self.new_text)
                        file_path.write_text(new_content, encoding="utf-8")
                        print(f"  [cyan]Replaced text[/] in {file_path.relative_to(work_dir)}")
                except UnicodeDecodeError:
                    # Skip binary files
                    pass


@dataclass
class CreateFile(FileTransformation):
    """Create a new file with given content."""

    file_path: str
    content: str

    def apply(self, work_dir: Path) -> None:
        file_path = work_dir / self.file_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(self.content, encoding="utf-8")
        print(f"  [cyan]Created[/] {self.file_path}")


@dataclass
class DeleteDirectory(FileTransformation):
    """Recursively delete a directory."""

    dir_path: str

    def apply(self, work_dir: Path) -> None:
        target_dir = work_dir / self.dir_path
        if target_dir.exists() and target_dir.is_dir():
            shutil.rmtree(target_dir)
            print(f"  [cyan]Deleted directory[/] {self.dir_path}")


PLUGINS = {
    "HRDevHelper": PluginConfig(
        name="HRDevHelper",
        repo_url="https://github.com/patois/HRDevHelper.git",
        commit="042f8e083068ad27c2fa2e4903ee2f4983d886a7",
        include_files=[
            "hrdevhelper.py",
            "hrdh/**",
            "LICENSE",
            "README.md",
        ],
        exclude_files=[
            "rsrc/**",
        ],
        transformations=[
            MoveFile("hrdevhelper.py", "hrdh/hrdevhelper.py"),
            ReplaceText("*.py", "from hrdevhelper import HRDevHelper", "# from hrdevhelper import HRDevHelper"),
            CreateFile("pyproject.toml", HRDEVHELPER_PYPROJECT),
        ],
    ),
    "deREFerencing": PluginConfig(
        name="deREFerencing",
        repo_url="https://github.com/danigargu/deREferencing.git",
        commit="259685bce8ab4ba0371ec6d13446cc553df2689b",
        include_files=[
            "dereferencing.py",
            "dereferencing/**",
            "LICENSE",
            "README.md",
        ],
        transformations=[
            MoveFile("dereferencing.py", "dereferencing/plugin.py"),
            CreateFile("pyproject.toml", DEREFERENCING_PYPROJECT),
        ],
    ),
    "ida-terminal-plugin": PluginConfig(
        name="ida-terminal-plugin",
        repo_url="https://github.com/HexRaysSA/ida-terminal-plugin.git",
        commit="efc8b1cef30a1a019bdbc7565108d160795bafea",
        include_files=[
            "index.py",
            "termqt/**",
            "config.example.py",
            "LICENSE",
            "README.md",
        ],
        transformations=[
            # Create the main plugin module directory
            MoveFile("index.py", "ida_terminal_module/plugin.py"),
            MoveFile("config.example.py", "ida_terminal_module/config.py"),
            # Move termqt into the module
            MoveFile("termqt", "ida_terminal_module/termqt"),
            # Create __init__.py for the main module
            CreateFile("ida_terminal_module/__init__.py", IDA_TERMINAL_INIT),
            # Create pyproject.toml
            CreateFile("pyproject.toml", IDA_TERMINAL_PYPROJECT),
            # Update the plugin.py to work with the new structure
            ReplaceText("plugin.py", "from termqt import Terminal", "from ida_terminal_module.termqt import Terminal"),
            ReplaceText(
                "plugin.py",
                "from termqt import TerminalPOSIXExecIO",
                "from ida_terminal_module.termqt import TerminalPOSIXExecIO",
            ),
            ReplaceText(
                "plugin.py",
                "from termqt import TerminalWinptyIO",
                "from ida_terminal_module.termqt import TerminalWinptyIO",
            ),
            # Note: config loading works fine as-is since we provide a default config.py
        ],
    ),
    "LazyIDA": PluginConfig(
        name="LazyIDA",
        repo_url="https://github.com/L4ys/LazyIDA.git",
        commit="9194babbeaf67e392f88e3ea87f0bf4fdc3f5982",
        include_files=[
            "LazyIDA.py",
            "LICENSE",
            "README.md",
        ],
        transformations=[
            # Move the main plugin file into a package structure
            MoveFile("LazyIDA.py", "lazyida/plugin.py"),
            # Create __init__.py for the package
            CreateFile("lazyida/__init__.py", "# LazyIDA Plugin Package"),
            # Create pyproject.toml
            CreateFile("pyproject.toml", LAZYIDA_PYPROJECT),
        ],
    ),
    "SwiftStringInspector": PluginConfig(
        name="SwiftStringInspector",
        repo_url="https://github.com/keowu/swiftstringinspector.git",
        commit="0ef03a928eeee9586ce706fdddd89e4c91359bb3",
        include_files=[
            "swift_string_inspector.py",
            "LICENSE",
            "README.md",
        ],
        transformations=[
            # Move the main plugin file into a package structure
            MoveFile("swift_string_inspector.py", "swiftstringinspector/plugin.py"),
            # Create __init__.py for the package
            CreateFile("swiftstringinspector/__init__.py", "# SwiftStringInspector Plugin Package"),
            # Create pyproject.toml
            CreateFile("pyproject.toml", SWIFTSTRINGINSPECTOR_PYPROJECT),
        ],
    ),
    "xrefer": PluginConfig(
        name="xrefer",
        repo_url="https://github.com/mandiant/xrefer.git",
        commit="3123c65484bfcacc002b8527016ac036b5ea5260",
        include_files=[
            "plugins/xrefer/**",
            # "plugins/xrefer.py",
            "LICENSE",
            "README.md",
        ],
        transformations=[
            MoveFile("plugins/xrefer", "xrefer"),
            DeleteDirectory("plugins"),
            # this file has some manual path fixups,
            # which we do ourselves here,
            # so we provide our own entrypoint.
            # MoveFile("plugins/xrefer.py", "xrefer/plugin.py"),
            CreateFile("xrefer/entry.py", XREFER_ENTRY),
            CreateFile("pyproject.toml", XREFER_PYPROJECT),
        ],
    ),
    "HexRaysPyTools": PluginConfig(
        name="HexRaysPyTools",
        repo_url="https://github.com/igogo-x86/HexRaysPyTools.git",
        commit="b8ebf757a92fda934c35c418fc55bfdd6fc8e67c",
        include_files=[
            "HexRaysPyTools.py",
            "HexRaysPyTools/**",
            "readme.md",
        ],
        transformations=[
            MoveFile("HexRaysPyTools.py", "HexRaysPyTools/plugin.py"),
            CreateFile("pyproject.toml", HEXRAYSPYTOOLS_PYPROJECT),
        ],
    ),
    "IDAFuzzy": PluginConfig(
        name="IDAFuzzy",
        repo_url="https://github.com/Ga-ryo/IDAFuzzy.git",
        commit="afd3b34d1fbd2a389f9975de83d5ab46f78aedb6",
        include_files=[
            "ida_fuzzy.py",
            "LICENSE",
            "README.md",
        ],
        transformations=[
            # Move the main plugin file into a package structure
            MoveFile("ida_fuzzy.py", "idafuzzy/plugin.py"),
            # Create __init__.py for the package
            CreateFile("idafuzzy/__init__.py", "# IDAFuzzy Plugin Package"),
            # Create pyproject.toml
            CreateFile("pyproject.toml", IDAFUZZY_PYPROJECT),
        ],
    ),
    "hexlight": PluginConfig(
        name="hexlight",
        repo_url="https://github.com/stevemk14ebr/RETools.git",
        commit="9501332bf02688d3a4b31d85a25349671767be98",
        include_files=[
            "IdaScripts/plugins/hexlight.py",
        ],
        transformations=[
            # Move the main plugin file into a package structure
            MoveFile("IdaScripts/plugins/hexlight.py", "hexlight/plugin.py"),
            # Clean up the intermediate directory
            DeleteDirectory("IdaScripts"),
            # Create __init__.py for the package
            CreateFile("hexlight/__init__.py", "# Hexlight Plugin Package"),
            # Create pyproject.toml
            CreateFile("pyproject.toml", HEXLIGHT_PYPROJECT),
        ],
    ),
    "string-from-selection": PluginConfig(
        name="string-from-selection",
        repo_url="https://github.com/stevemk14ebr/RETools.git",
        commit="9501332bf02688d3a4b31d85a25349671767be98",
        include_files=[
            "IdaScripts/plugins/string_from_selection.py",
        ],
        transformations=[
            # Move the main plugin file into a package structure
            MoveFile("IdaScripts/plugins/string_from_selection.py", "string_from_selection/plugin.py"),
            # Clean up the intermediate directory
            DeleteDirectory("IdaScripts"),
            # Create __init__.py for the package
            CreateFile("string_from_selection/__init__.py", "# String From Selection Plugin Package"),
            # Create pyproject.toml
            CreateFile("pyproject.toml", STRING_FROM_SELECTION_PYPROJECT),
        ],
    ),
}


def run_command(cmd: List[str], cwd: Optional[Path] = None) -> None:
    """Run a shell command and handle errors."""
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{result.stderr}")


def matches_pattern(file_path: Path, patterns: List[str]) -> bool:
    """Check if a file matches any of the given patterns."""
    path_str = str(file_path)
    for pattern in patterns:
        # Convert glob patterns to work with full paths
        if "**" in pattern:
            # Handle recursive patterns
            if fnmatch.fnmatch(path_str, pattern) or fnmatch.fnmatch(path_str, f"*/{pattern}"):
                return True
        else:
            # Handle simple patterns
            if fnmatch.fnmatch(file_path.name, pattern) or fnmatch.fnmatch(path_str, pattern):
                return True
    return False


def print_directory_tree(directory: Path, prefix: str = "", is_last: bool = True) -> None:
    """Print directory contents in ASCII tree format."""
    if not directory.exists():
        return

    # Get all items and sort them (directories first, then files)
    items = sorted(directory.iterdir(), key=lambda x: (x.is_file(), x.name.lower()))
    if directory.name == ".git":
        items = []

    for i, item in enumerate(items):
        is_last_item = i == len(items) - 1

        # Choose the appropriate tree character
        if is_last_item:
            current_prefix = "[grey69]└──[/] "
            next_prefix = prefix + "    "
        else:
            current_prefix = "[grey69]├──[/] "
            next_prefix = prefix + "[grey69]│[/]   "

        print(f"{prefix}{current_prefix}{item.name}")

        # Recursively print subdirectories
        if item.is_dir():
            print_directory_tree(item, next_prefix, is_last_item)


def copy_matching_files(src_dir: Path, dst_dir: Path, include_patterns: List[str], exclude_patterns: List[str]) -> None:
    """Copy files matching include patterns but not exclude patterns."""
    for src_file in src_dir.rglob("*"):
        if not src_file.is_file():
            continue

        rel_path = src_file.relative_to(src_dir)

        # Check if file matches include patterns
        if not matches_pattern(rel_path, include_patterns):
            continue

        # Check if file matches exclude patterns
        if exclude_patterns and matches_pattern(rel_path, exclude_patterns):
            continue

        # Copy the file
        dst_file = dst_dir / rel_path
        dst_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_file, dst_file)
        print(f"  [cyan]Copied[/] {rel_path}")


def migrate_plugin(plugin_name: str, config: PluginConfig, output_dir: Path) -> None:
    """Migrate a single plugin."""
    print(f"\n[bold yellow]Migrating[/] {plugin_name}...")

    plugin_output_dir = output_dir / plugin_name

    # Clean output directory
    if plugin_output_dir.exists():
        shutil.rmtree(plugin_output_dir)
    plugin_output_dir.mkdir(parents=True)

    # Clone repository to temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        repo_dir = temp_path / "repo"

        print(f"  [bold yellow]Cloning[/] {config.repo_url}...")
        run_command(["git", "clone", config.repo_url, str(repo_dir)])

        print(f"  [bold yellow]Checking out[/] {config.commit}...")
        run_command(["git", "checkout", config.commit], cwd=repo_dir)

        # Show directory structure before transformations
        print("  [bold yellow]Full repository contents[/]:")
        print(f"  {repo_dir}")
        print_directory_tree(repo_dir, prefix="  ")

        # Copy matching files
        print("  [bold yellow]Copying files[/]...")
        copy_matching_files(repo_dir, plugin_output_dir, config.include_files, config.exclude_files)

        # Apply transformations
        print("  [bold yellow]Applying transformations[/]...")
        for transformation in config.transformations:
            transformation.apply(plugin_output_dir)

        # Show directory structure after transformations
        print("  [bold yellow]Directory structure after transformations[/]:")
        print(f"  {plugin_output_dir}")
        print_directory_tree(plugin_output_dir, prefix="  ")

    print(f"  [green]✓ {plugin_name} migrated successfully[/]")


def main():
    import sys

    # Determine which plugins to migrate
    if len(sys.argv) > 1:
        plugin_names = sys.argv[1:]
        for name in plugin_names:
            if name not in PLUGINS:
                print(f"Error: Unknown plugin '{name}'. Available: {', '.join(PLUGINS.keys())}")
                sys.exit(1)
    else:
        plugin_names = list(PLUGINS.keys())

    output_dir = Path("third_party")

    for plugin_name in plugin_names:
        config = PLUGINS[plugin_name]
        migrate_plugin(plugin_name, config, output_dir)

    print(f"\n[green]✓ Migration complete![/] Plugins available in {output_dir}/")


if __name__ == "__main__":
    main()
