# As a IDA Pro User

Here's how to use the IDA Pro Plugin Manager to discover, install, and manage IDA Pro plugins.

Quickstart:
```bash
# one time installation
$ pip install idapro-plugin-manager
$ ippm register

# find some plugins
$ ippm list
$ ippm show williballenthin-hint-calls-ida-plugin
$ ippm install williballenthin-hint-calls-ida-plugin
$ ippm update williballenthin-hint-calls-ida-plugin
$ ippm update-all
$ ippm remove williballenthin-hint-calls-ida-plugin
```

But let's learn more:
  - [Installation Instructions](#installation)
    - [Fetch the package from PyPI](#1-fetch-the-package-from-pypi)
    - [Register the plugin manager in IDA Pro](#2-register-the-plugin-manager-in-ida-pro)
  - [Command-Line Tool (`ippm`)](#command-line-tool-ippm)
    - [Listing Available Plugins](#listing-available-plugins)
    - [Showing Plugin Details](#showing-plugin-details)
    - [Installing Plugins](#installing-plugins)
    - [Updating Plugins](#updating-plugins)
    - [Updating All Plugins](#updating-all-plugins)
    - [Removing Plugins](#removing-plugins)


## Installation

There are two steps:

  1. to fetch the plugin manager
  2. to register the plugin manager with IDA Pro

Then you can install plugins via `ippm` directly.

### 1. Fetch the package from PyPI

The plugin manager is distributed via PyPI, so install it via `pip`:

```bash
$ pip install idapro-plugin-manager
```

Make sure to use the `pip` from your IDAPython installation, which [I recommend to be a virtual environment](https://williballenthin.com/post/using-a-virtualenv-for-idapython/).

You can find the location of the `pip` executable by running the following within your IDAPython console in IDA Pro:

```python
Python>import subprocess
Python>subprocess.run(["which", "pip"], capture_output=True).stdout.decode("utf-8").strip()
'/Users/user/.idapro/venv/bin/pip'
```

(TODO: check this works on Windows, too.)

### 2. Register the plugin manager in IDA Pro

Run the following command to automatically register the plugin manager with IDA Pro:

```bash
$ ippm register
```

This installs the bootstrap plugin to your IDA Pro plugins directory. You only have to do this once, even if you upgrade IDA.

## Command-Line Tool (`ippm`)

The IDA Pro Plugin Manager also comes with a command-line tool, `ippm`, to help you discover and manage plugins.

### Listing Available Plugins

To see a list of IDA Pro plugins available on PyPI, use the `list` command:

```bash
$ ippm list
                                      Available IDA Pro Plugins on PyPI
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Name                                       ┃ Last Release         ┃ Summary                                ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ basic-ida-plugin (installed)               │ 0.1.0 (Jun 02, 2025) │ Example IDA Plugin                     │
│ multifile-ida-plugin                       │ 0.1.0 (Jun 02, 2025) │ Example IDA Plugin with multiple files │
│ williballenthin-colorize-calls-ida-plugin  │ 0.1.0 (Jun 03, 2025) │ IDA Pro plugin to colorize call        │
│                                            │                      │ instructions and add a prefix          │
│ williballenthin-hint-calls-ida-plugin      │ 0.1.2 (Jun 03, 2025) │ IDA Pro plugin to display popup        │
│                                            │                      │ function hints for the referenced      │
│                                            │                      │ calls and strings                      │
│ williballenthin-navband-visited-ida-plugin │ 0.1.0 (Jun 03, 2025) │ IDA Pro plugin to highlight visited    │
│                                            │                      │ addresses in the navigation band.      │
│ williballenthin-tag-func-ida-plugin        │ 0.1.0 (Jun 03, 2025) │ IDA Pro plugin for tagging functions   │
│                                            │                      │ into folders                           │
└────────────────────────────────────────────┴──────────────────────┴────────────────────────────────────────┘
```

This command queries PyPI for packages that appear to be IDA Pro plugins (based on naming conventions like `idapro-plugin-*`, `*-ida-plugin`, etc.). 


### Showing Plugin Details

To view detailed information about a specific plugin, use the `show` command followed by the plugin's name as it appears on PyPI:

```bash
$ ippm show williballenthin-tag-func-ida-plugin
┌─────────────────────────────┬──────────────────────────────────────────────────────────────────────────────┐
│ Name                        │ williballenthin-tag-func-ida-plugin                                          │
│ Version                     │ 0.1.0                                                                        │
│ Summary                     │ IDA Pro plugin for tagging functions into folders                            │
│ Author                      │ Willi Ballenthin <willi.ballenthin@gmail.com>                                │
│ License                     │ Apache-2.0                                                                   │
│ Requires Python             │ >=3.9                                                                        │
│ Package URL                 │ https://pypi.org/project/williballenthin-tag-func-ida-plugin/                │
│ Project URL                 │ https://pypi.org/project/williballenthin-tag-func-ida-plugin/                │
│ Release URL                 │ https://pypi.org/project/williballenthin-tag-func-ida-plugin/0.1.0/          │
│ Version History             │ 0.1.0           Jun 03, 2025                                                 │
│ Description (text/markdown) │ ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓ │
│                             │ ┃                       Tag Function IDA Pro Plugin                        ┃ │
│                             │ ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛ │
│                             │                                                                              │
│                             │ IDA Pro plugin for tagging functions into folders.                           │
│                             │                                                                              │
│                             │                                                                              │
│                             │                                 Installation                                 │
│                             │                                                                              │
│                             │ Assuming you have the IDA Pro Plugin Manager, install via pip:               │
│                             │                                                                              │
│                             │                                                                              │
│                             │  pip install williballenthin-tag-func-ida-plugin                             │
│                             │                                                                              │
│                             │                                                                              │
│                             │ Make sure to use the pip from your IDAPython installation.                   │
└─────────────────────────────┴──────────────────────────────────────────────────────────────────────────────
```

### Installing Plugins

To install a plugin:

```bash
$ ippm install multifile-ida-plugin
Installing plugin: multifile-ida-plugin
Successfully installed multifile-ida-plugin
  Collecting multifile-ida-plugin
    Downloading multifile_ida_plugin-0.1.0-py3-none-any.whl.metadata (1.8 kB)
  Downloading multifile_ida_plugin-0.1.0-py3-none-any.whl (2.8 kB)
  Installing collected packages: multifile-ida-plugin
  Successfully installed multifile-ida-plugin-0.1.0
```


### Updating Plugins
To update a plugin to the latest version:

```bash
$ ippm update multifile-ida-plugin
Updating plugin: multifile-ida-plugin
multifile-ida-plugin is already up to date
  Requirement already satisfied: multifile-ida-plugin in ./.venv/lib/python3.12/site-packages (0.1.0)
```

### Updating All Plugins

To update all installed plugins to their latest versions:

```bash
$ ippm update-all 
Finding installed IDA Pro plugins...
Found 2 installed IDA Pro plugin(s):
  - basic-ida-plugin
  - multifile-ida-plugin

Checking for updates...
  basic-ida-plugin: 0.1.0 (up to date)
  multifile-ida-plugin: 0.1.0 (up to date)

All plugins are up to date!
```

### Removing Plugins

To remove an installed plugin:

```bash
$ ippm remove multifile-ida-plugin
Removing plugin: multifile-ida-plugin
Successfully removed multifile-ida-plugin
```

