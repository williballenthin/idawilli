# IDA Pro Plugin Manager - 3rd Party Plugin Migration

This document contains lessons learned and best practices for migrating 3rd party IDA Pro plugins into the plugin manager format.

## Commands for Development

```bash
# Import all plugins
just import

# Import specific plugin
just import-lazyida
just import-hrdevhelper
just import-dereferencing
just import-ida-terminal-plugin

# Build all plugins
just build

# Build specific plugin
just build-lazyida

# Test all plugins
just test

# Test specific plugin
just test-lazyida

# Clean up
just clean
just clean-lazyida
```

## Steps to Add a New 3rd Party Plugin

### 1. Research the Plugin Repository

Before adding a plugin, examine its structure:
- Visit the GitHub repository
- Check the main plugin file(s) and structure
- Look for dependencies
- Identify the license and README files
- Get the latest commit hash for pinning

#### Repository Structure Deep Dive
Before creating the migration config, carefully examine the actual file structure:
- Don't assume file locations based on README descriptions
- Use web interface or clone locally to see exact structure
- Check for subdirectories that need to be preserved
- Identify the actual main plugin file location

**Example - hex-highlighter had unexpected structure:**
- README mentioned `block_highlight.py` but actual structure was:
  - `plugins/highlighter_plugin.py` (main file)
  - `plugins/ida_hex_highlighter/` (subdirectory with core logic)

**Example for LazyIDA:**
- Repository: https://github.com/L4ys/LazyIDA
- Single file plugin: `LazyIDA.py`
- Has LICENSE and README.md
- Latest commit: `9194babbeaf67e392f88e3ea87f0bf4fdc3f5982`

### 2. Update migrate_plugins.py

Add three main components:

#### A. Create pyproject.toml template
```python
PLUGIN_NAME_PYPROJECT = """[project]
name = "3p-PluginName-ida-plugin"
authors = [
  {name = "Original Author"},
]
maintainers = [
  {name = "Willi Ballenthin", email = "willi.ballenthin@gmail.com"},
]
description = "Plugin description"
version = "2025.6.12"
readme = "README.md"
license-files = [ "LICENSE" ]
requires-python = ">=3.9"
dependencies = [
    # Add any dependencies here, if needed
]

[project.urls]
source = "https://github.com/original/repo"
repository = "https://github.com/original/repo"
plugin-source = "https://github.com/williballenthin/idawilli/tree/master/plugins/plugin-manager/3p-plugins/"

[project.entry-points.'idapro.plugins']
idapython = "plugin_package.plugin"

[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"
"""
```

#### B. Add plugin configuration to PLUGINS dictionary
```python
"PluginName": PluginConfig(
    name="PluginName",
    repo_url="https://github.com/original/repo.git",
    commit="latest_commit_hash",
    include_files=[
        "plugin_package/**",
        "main_plugin_file.py",
        "LICENSE",
        "README.md",
        # Add any subdirectories with "**"
    ],
    exclude_files=[
        # Optional: files to exclude
    ],
    transformations=[
        # if necessary, move the source directories first
        MoveFile("PluginPackage", "plugin_package"),
        # after the directory structure is created, move the main plugin file.
        MoveFile("main_plugin_file.py", "plugin_package/plugin.py"),
        # If it doesn't exist, create package __init__.py
        CreateFile("plugin_package/__init__.py", ""),
        CreateFile("pyproject.toml", PLUGIN_NAME_PYPROJECT),
        # Optional: fix imports due to package structure changes.
        # always use absolute imports rather than package-relative imports
        # because IDA may not maintain the current package metadata.
        # ReplaceText("*.py", "from .old_import", "from package_plugin.new_import"),
    ]
),
```

### 3. Update .justfile

Add commands for the new plugin:
```bash
import-pluginname:
    python migrate_plugins.py PluginName

clean-pluginname:
    rm -rf third_party/PluginName

build-pluginname:
    python -m build --wheel third_party/PluginName

test-pluginname:
    python ../scripts/test_plugin.py third_party/PluginName/dist/*.whl
```

Update the bulk commands:
```bash
import:
    python migrate_plugins.py

build:
    just build-hrdevhelper
    just build-dereferencing
    just build-ida-terminal-plugin
    just build-pluginname  # Add new plugin

test:
    just test-hrdevhelper
    just test-dereferencing
    just test-ida-terminal-plugin
    just test-pluginname  # Add new plugin
```

### 4. Test the Migration

```bash
cd plugins/plugin-manager/3p-plugins
eval "$(direnv export zsh)"  # Load development environment
python migrate_plugins.py PluginName
python -m build --wheel third_party/PluginName
python ../scripts/test_plugin.py third_party/PluginName/dist/*.whl
```

### 5. Update Documentation

#### A. Add to plugins/plugin-manager/README.md
Add an entry to the plugins table:
```markdown
| [3p-PluginName-ida-plugin](https://github.com/original/repo) | Plugin description |
```

#### B. Create GitHub workflow
Copy and modify an existing workflow file (e.g., `.github/workflows/publish-3p-hrdevhelper-ida-plugin.yml`):
- Update the workflow name
- Change the just commands to use the new plugin name
- Update the packages-dir path

### 6. Commit Changes

Commit all the changes:
- `migrate_plugins.py`
- `.justfile`
- `README.md`
- `.github/workflows/publish-3p-pluginname-ida-plugin.yml`

## Common Plugin Patterns

### Single File Plugins (like LazyIDA)
- Simple structure: just move the main `.py` file into a package
- Transformations: `MoveFile("Plugin.py", "package/plugin.py")`

### Multi-File Plugins (like ida-terminal-plugin)
- Include subdirectories with `"subdir/**"`
- Move subdirectories with `MoveFile("subdir", "package/subdir")`
- May need import fixes with `ReplaceText()`

### Plugins with Subdirectories and Complex Imports (like hex-highlighter)
- Include entire subdirectories: `"plugins/ida_hex_highlighter/**"`
- Move subdirectories preserving structure: `MoveFile("plugins/ida_hex_highlighter", "package_name/ida_hex_highlighter")`
- Fix import paths after restructuring: `ReplaceText("*.py", "from ida_hex_highlighter.module", "from package_name.ida_hex_highlighter.module")`

### Simple Plugins (like HRDevHelper)
- May have both a main file and subdirectory
- Move main file into the subdirectory
- Clean up circular imports

## Common Issues and Solutions

### Qt Import Issues
Some plugins use `from PyQt5.Qt import QApplication` which may not work in all IDA Pro versions. The test script will catch these, but they can be ignored if the plugin otherwise works.

### Import Path Issues After Restructuring
When moving files into packages, imports often break. Add transformations to fix them:
```python
ReplaceText("plugin.py", "from original.import.path", "from new_package.import.path")
```
Test thoroughly after import changes.

### Dependency Management
- Most IDA plugins should have minimal dependencies
- Use `dependencies = []` in pyproject.toml

## Testing Notes

The test script (`../scripts/test_plugin.py`) will:
1. Install the plugin in a temporary environment
2. Load it in a minimal IDA Pro session
3. Check for import errors and basic functionality

Some import errors (especially Qt-related) can be ignored if they don't prevent the plugin from loading in real IDA Pro usage.

## Lessons Learned from LazyIDA Migration

1. **Repository Structure Analysis**: Always examine the source repository structure first to understand what files need to be included
2. **Commit Pinning**: Use specific commit hashes rather than branches for reproducible builds
3. **Package Structure**: Single-file plugins need to be restructured into proper Python packages
4. **Entry Points**: The entry point should reference the moved plugin file location
5. **Testing Environment**: The development environment setup with direnv is crucial for consistent builds
6. **Documentation**: Always update both the README and create the GitHub workflow for completeness
7. **Qt Compatibility**: Qt import issues are common but often don't prevent real-world plugin usage

## File Locations Reference

- Migration script: `plugins/plugin-manager/3p-plugins/migrate_plugins.py`
- Build commands: `plugins/plugin-manager/3p-plugins/.justfile`
- Documentation: `plugins/plugin-manager/README.md`
- GitHub workflows: `.github/workflows/publish-3p-*-ida-plugin.yml`
- Test script: `plugins/plugin-manager/scripts/test_plugin.py`