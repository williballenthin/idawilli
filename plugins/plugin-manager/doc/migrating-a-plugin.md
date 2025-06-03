# Migrating an IDA Pro Plugin to Plugin Manager Format

Migrating an IDA Pro plugin to the format supported by the IDA Pro Plugin Manager involves structuring the plugin as a Python package. This allows it to be installed via `pip` and discovered by the plugin manager using Python's entry points mechanism.

This guide outlines the files that need to be moved, changed, or created, and describes the necessary modifications.

## Overview of Changes

The core idea is to package your existing IDA plugin (typically a single `.py` file or a small collection of files) into a standard Python package structure. This involves:

1.  Creating a dedicated directory for your plugin.
2.  Moving your plugin's Python code into this directory.
3.  Adding a `pyproject.toml` file to define the package metadata and entry points.
4.  Adding or updating a `README.md` file for documentation.
5.  Optionally, creating a GitHub Actions workflow for automated building and publishing to PyPI.

## Files to be Moved, Changed, or Created

Here's a breakdown of the files involved and the changes required:

### 1. Plugin's Main Python File (e.g., `original_plugin.py`)

*   **Move:**
    *   This file is moved into a new dedicated directory for the plugin. For example, if your plugin is named `my_plugin`, you might create `plugins/my_plugin/` and move your file to `plugins/my_plugin/my_plugin.py`.
    *   The filename should ideally match the intended Python module name (e.g., `tag_func.py` for a module named `tag_func`).

### 2. `pyproject.toml` (New File)

*   **Create:** This file must be created in the root of your plugin's new directory (e.g., `plugins/my_plugin/pyproject.toml`).
*   **Content/Changes:** This file uses TOML syntax to define project metadata and build information.

    ```toml
    [project]
    # Distribution name of the package on PyPI (e.g., "williballenthin-my-plugin-ida-plugin")
    # This is project-specific.
    name = "your-plugin-name-ida-plugin"

    # Version number of the plugin. Project-specific.
    version = "0.1.0"

    # List of authors. Project-specific.
    authors = [
      {name = "Your Name", email = "your.email@example.com"},
    ]

    # A brief description of the plugin. Project-specific.
    description = "An amazing IDA Pro plugin that does X, Y, and Z."

    # Specifies the README file. Typically "README.md".
    readme = "README.md"

    # License for the plugin. Project-specific.
    license = "Apache-2.0"  # Or your chosen license

    # Minimum Python version required. Often similar across plugins.
    requires-python = ">=3.9"

    # List of runtime dependencies for the plugin. Project-specific.
    # If your plugin doesn't have external dependencies, this can be empty.
    dependencies = []

    # This section is crucial for the IDA Pro Plugin Manager.
    # It tells the manager how to find and load your plugin.
    [project.entry-points.'idapro.plugins']
    # 'idapython' is a conventional key.
    # "module_name" is the name of your Python module (e.g., "my_plugin" if your file is my_plugin.py).
    # This is project-specific.
    idapython = "my_plugin"

    # Standard build system configuration for setuptools.
    [build-system]
    requires = ["setuptools>=61.0"]
    build-backend = "setuptools.build_meta"

    # Configuration for setuptools.
    [tool.setuptools]
    # Specifies the Python module(s) to be included in the package.
    # This should match the "module_name" used in the entry point.
    # This is project-specific.
    py-modules = ["my_plugin"]
    ```

    *   **`[project]` section:**
        *   `name`: The unique distribution name for PyPI. *Project-specific.*
        *   `authors`: Your author details. *Project-specific.*
        *   `description`: Plugin's purpose. *Project-specific.*
        *   `version`: Plugin's version. *Project-specific.*
        *   `readme`: Usually `"README.md"`. *Boilerplate structure.*
        *   `license`: Your chosen license. *Project-specific.*
        *   `requires-python`: Typically `">=3.9"` or similar. *Often boilerplate.*
        *   `dependencies`: Any external Python libraries your plugin needs. *Project-specific.*
    *   **`[project.entry-points.'idapro.plugins']` section:**
        *   `idapython = "module_name"`: This is the key for discovery. `idapython` is the standard group. `module_name` is the name of your main plugin Python file (without the `.py` extension). *The group `idapro.plugins` and key `idapython` are boilerplate; the module name is project-specific.*
    *   **`[build-system]` section:**
        *   Defines build tool requirements (e.g., `setuptools`). *Generally boilerplate.*
    *   **`[tool.setuptools]` section:**
        *   `py-modules = ["module_name"]`: Lists the top-level Python modules to include. This should match the `module_name` from the entry point. *Project-specific module name.*

### 3. `README.md` (New or Updated File)

*   **Create/Update:** Place this file in your plugin's new directory (e.g., `plugins/my_plugin/README.md`).
*   **Content/Changes:**
    *   **Description:** Explain what your plugin does, its features, and how to use it. *Project-specific content.*
    *   **Installation:** Provide clear installation instructions. For plugins managed by the IDA Pro Plugin Manager, this usually involves `pip install your-package-name`.
        ```markdown
        ## Installation

        Assuming you have the [IDA Pro Plugin Manager](https://github.com/williballenthin/idawilli/tree/master/plugins/plugin-manager) (or a compatible setup that recognizes `idapro.plugins` entry points), install via pip:

        ```bash
        pip install your-plugin-name-ida-plugin
        ```

        Make sure to use the `pip` associated with your IDAPython environment.
        ```
        *The installation command structure is boilerplate; the package name is project-specific.*
    *   **Publishing (Optional):** If you publish to PyPI, you might include a section linking to its PyPI page and the GitHub Actions workflow file. *Project-specific links and names.*

### 4. GitHub Actions Workflow File (e.g., `.github/workflows/publish-my-plugin.yml`) (New File, Optional)

If you plan to publish your plugin to PyPI automatically, you can create a GitHub Actions workflow.

*   **Create:** This file goes into the `.github/workflows/` directory of your repository.
*   **Content/Changes:** This YAML file defines the CI/CD pipeline.

    ```yaml
    # .github/workflows/publish-my-plugin.yml
    name: publish your-plugin-name-ida-plugin to pypi

    on:
      # Example trigger: manual dispatch
      workflow_dispatch:
      # Example trigger: when a new tag starting with 'v' is pushed
      # push:
      #   tags:
      #     - 'v*'

    permissions:
      contents: read
      id-token: write # Required for PyPI trusted publishing

    jobs:
      pypi-publish:
        name: build and publish
        runs-on: ubuntu-latest
        environment:
          name: release
        permissions:
          id-token: write # Required for PyPI trusted publishing

        steps:
          - name: Checkout repository
            uses: actions/checkout@v4

          - name: Set up Python
            uses: actions/setup-python@v5
            with:
              python-version: '3.9'

          - name: Install dependencies (build tools)
            run: |
              python -m pip install --upgrade pip
              pip install setuptools build

          - name: Build package
            run: |
              # Navigate to your plugin's directory if pyproject.toml is not at the repo root
              cd plugins/my_plugin
              python -m build

          - name: Publish package to PyPI
            uses: pypa/gh-action-pypi-publish@release/v1
            with:
              packages-dir: plugins/my_plugin/dist  # Path to the built package(s)

          - name: Upload package artifacts
            uses: actions/upload-artifact@v4
            with:
              name: python-package
              path: plugins/my_plugin/dist/*
    ```
    *   `name`: A descriptive name for the workflow. *Project-specific.*
    *   `jobs.pypi-publish.steps`:
        *   `Build package`:
            *   `cd path/to/plugin_dir`: Navigates to your plugin's directory. *Project-specific path.*
        *   `Publish package to PyPI`:
            *   `packages-dir: path/to/plugin_dir/dist`: Specifies where the built package (`.tar.gz`, `.whl`) is located. *Project-specific path.*
        *   `Upload package artifacts`:
            *   `path: path/to/plugin_dir/dist/*`: Specifies the built artifacts to upload. *Project-specific path.*

## Summary of Data Types

When migrating, some information will be standard (boilerplate), while other parts are unique to your plugin.

### Typically Same (Boilerplate)

*   The overall structure of `pyproject.toml` (presence of `[project]`, `[project.entry-points.'idapro.plugins']`, `[build-system]`, `[tool.setuptools]`).
*   Common keys in `pyproject.toml` like `readme = "README.md"`, `requires-python`.
*   The `[build-system]` section in `pyproject.toml` is usually standard for `setuptools`.
*   The entry point group `idapro.plugins` and the conventional key `idapython` used within it.
*   The general structure of a GitHub Actions workflow for building and publishing a Python package (checkout, setup Python, install build tools, build command, PyPI publish action).

### Specific to the Project

*   **Plugin Code:** The actual Python code and logic of your plugin.
*   **`pyproject.toml` values:**
    *   `name` (the PyPI package name)
    *   `authors`
    *   `description`
    *   `version`
    *   `license`
    *   `dependencies` (if any)
    *   The Python `module_name` used in `[project.entry-points.'idapro.plugins']` (e.g., `idapython = "my_plugin"`) and in `[tool.setuptools]` (e.g., `py-modules = ["my_plugin"]`).
*   **`README.md` content:** Specific details about your plugin, its features, and advanced usage.
*   **GitHub Actions Workflow:**
    *   The workflow `name`.
    *   Specific paths to your plugin directory used in `cd` commands, `packages-dir` for publishing, and artifact `path`.
*   **PyPI Package Name:** The unique name under which your plugin is registered on PyPI.
*   **Module/File Names:** The name of your plugin's Python file(s) and the corresponding module name.

By following these steps, you can adapt your existing IDA Pro plugin to be compatible with the IDA Pro Plugin Manager, making it easier to distribute, install, and manage.
