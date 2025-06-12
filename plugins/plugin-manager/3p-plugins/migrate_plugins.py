#!/usr/bin/env python3
"""
Plugin Migration Script

Replaces copybara for migrating 3rd-party IDA plugins.
Each plugin is migrated to its own directory to avoid conflicts.

Usage:
    python migrate_plugins.py [plugin_name]
    python migrate_plugins.py  # migrates all plugins
"""

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional
import fnmatch
import re


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
            print(f"  Moved {self.src} -> {self.dst}")


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
                    content = file_path.read_text(encoding='utf-8')
                    if self.old_text in content:
                        new_content = content.replace(self.old_text, self.new_text)
                        file_path.write_text(new_content, encoding='utf-8')
                        print(f"  Replaced text in {file_path.relative_to(work_dir)}")
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
        file_path.write_text(self.content, encoding='utf-8')
        print(f"  Created {self.file_path}")





# Plugin Configurations
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
        ]
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
        ]
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
            ReplaceText("plugin.py", "from termqt import TerminalPOSIXExecIO", "from ida_terminal_module.termqt import TerminalPOSIXExecIO"),
            ReplaceText("plugin.py", "from termqt import TerminalWinptyIO", "from ida_terminal_module.termqt import TerminalWinptyIO"),
            # Note: config loading works fine as-is since we provide a default config.py
        ]
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
        ]
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
        ]
    ),
}


def run_command(cmd: List[str], cwd: Path = None) -> None:
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
        print(f"  Copied {rel_path}")


def migrate_plugin(plugin_name: str, config: PluginConfig, output_dir: Path) -> None:
    """Migrate a single plugin."""
    print(f"\nMigrating {plugin_name}...")
    
    plugin_output_dir = output_dir / plugin_name
    
    # Clean output directory
    if plugin_output_dir.exists():
        shutil.rmtree(plugin_output_dir)
    plugin_output_dir.mkdir(parents=True)
    
    # Clone repository to temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        repo_dir = temp_path / "repo"
        
        print(f"  Cloning {config.repo_url}...")
        run_command(["git", "clone", config.repo_url, str(repo_dir)])
        
        print(f"  Checking out {config.commit}...")
        run_command(["git", "checkout", config.commit], cwd=repo_dir)
        
        # Copy matching files
        print(f"  Copying files...")
        copy_matching_files(repo_dir, plugin_output_dir, config.include_files, config.exclude_files)
        
        # Apply transformations
        print(f"  Applying transformations...")
        for transformation in config.transformations:
            transformation.apply(plugin_output_dir)
    
    print(f"  ✓ {plugin_name} migrated successfully")


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
    
    print(f"\n✓ Migration complete! Plugins available in {output_dir}/")


if __name__ == "__main__":
    main()
