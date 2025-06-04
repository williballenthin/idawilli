# Creating Offline PyPI Mirrors

The IDA Pro Plugin Manager includes a mirroring feature for creating local, offline archives of Python packages and their dependencies. This is useful for air-gapped environments, corporate networks with restricted internet access, or when you need a reliable offline backup of critical plugins. You can mirror available IDA plugins into a directory, archive them, and easily transfer them to another machine, where you can install them using pip.


Quickstart:

```bash
$ ippm mirror /tmp/repo

# now you can install packages from the local mirror
$ pip install --index-url file:///tmp/repo basic-ida-plugin
```

## Overview

The `mirror` command creates a [PEP 503](https://peps.python.org/pep-0503/) compliant local PyPI repository that can be used with standard Python package management tools like `pip`. The mirrored repository includes:

- Package files (both `.whl` and `.tar.gz` distributions)
- Complete dependency trees
- Proper HTML index pages for package discovery
- SHA256 integrity hashes for all files

## Basic Usage

### Mirror Specific Packages

To mirror one or more specific packages:

```bash
ippm mirror /path/to/local/repo package1 package2 package3
```

Example:
```bash
ippm mirror /tmp/repo basic-ida-plugin multifile-ida-plugin
```

### Mirror All IDA Pro Plugins

When no packages are specified, ippm will offer to mirror all available IDA Pro plugins:

```bash
ippm mirror ./ida-plugins-archive
```

This will prompt you to confirm downloading all discovered IDA Pro plugins from PyPI.

## Using the Mirrored Repository

Once created, you can use the mirrored repository with pip:

### Install from Local Mirror

```bash
# Install a specific package
pip install -i file:///path/to/repo package-name

# Install with pip pointing to your local mirror
pip install --index-url file:///path/to/repo package-name

# Use as an extra index (fallback to PyPI if not found locally)
pip install --extra-index-url file:///path/to/repo package-name
```

### Configure pip Permanently

You can configure pip to always use your local mirror by creating a `pip.conf` file:

**Linux/Mac** (`~/.pip/pip.conf`):
```ini
[global]
index-url = file:///path/to/repo
extra-index-url = https://pypi.org/simple/
```

**Windows** (`%APPDATA%\pip\pip.ini`):
```ini
[global]
index-url = file:///path/to/repo
extra-index-url = https://pypi.org/simple/
```

## Advanced Use Cases

### Continuous Integration

Include package mirroring in your CI pipeline to ensure reproducible builds:

```bash
# In your CI script
ippm mirror ./ci-cache required-package-1 required-package-2

# Use cached packages in subsequent builds
pip install -i file://$(pwd)/ci-cache package-name
```
