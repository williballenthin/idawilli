# IDA Pro Plugin Manager

The IDA Pro Plugin Manager is a tool to help you discover, install, and manage IDA Pro plugins distributed via a central index. It should be *very easy* for you extend the capabilities of IDA Pro with plugins, whether they are written in IDAPython or compiled languages like C/C++.

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

Read on for details:
  - [Installation Instructions](#installation)
  - [Command-Line Tool (`ippm`)](#command-line-tool-ippm)
  - [Packaging Plugins](#packaging-plugins)
  - [Entry Points](#entry-points)

## Installation

There are two steps:

  1. to fetch the plugin manager
  2. to register the plugin manager with IDA Pro

Then you can install plugins via `pip` directly.

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

## Packaging Plugins

Plugins are distributed via PyPI, which is usually (but not always) used for Python packages.
We use Python-style metadata, such as a `pyproject.toml` file, to describe the plugin. 

By adding an "entry point" for the `idapro.plugins` group,
we can register a plugin with the IDA Pro Plugin Manager.

Here are some example plugins:
  - [basic-ida-plugin](/plugins/plugin-manager/examples/basic-ida-plugin/)
  - [multifile-ida-plugin](/plugins/plugin-manager/examples/multifile-ida-plugin/)

Let's walk through `basic-ida-plugin`, which is a simple IDA plugin with a single file: `hello.py`.
(Recall that IDAPython plugins should have a function named `PLUGIN_ENTRY` that's used to initialize the plugin.)

The package structure looks like:

    basic-ida-plugin/
    ├── hello.py
    └── pyproject.toml

with the `pyproject.toml` contents:

```toml
[project]
name = "basic-ida-plugin"
...

[project.entry-points.'idapro.plugins']
idapython = 'hello'
```

and `hello.py` contents:

```py
import idaapi

class hello_plugmod_t(idaapi.plugmod_t):
    def run(self, arg):
        print("Hello world! (py)")
        return 0

class hello_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL | idaapi.PLUGIN_MULTI
    comment = "This is a comment"
    help = "This is help"
    wanted_name = "Hello Python plugin"
    wanted_hotkey = "Alt-F8"

    def init(self):
        print("hello from init")
        return hello_plugmod_t()

def PLUGIN_ENTRY():
    return hello_plugin_t()
```

The `pyproject.toml` entry point references `hello` Python module that contains the plugin code.
Our plugin manager knows how to inspect all installed Python packages
 and find plugins via the metadata, including `basic-ida-plugin`.

I packaged this plugin and uploaded it to PyPI, so you can install it like this:

    pip install basic-ida-plugin

If you have a local plugin in development, you can use other Python idioms, like:

    pip install --editable /path/to/basic-ida-plugin/source

There is a more comprehensive miration guide found in [doc/migrating-a-plugin.md](doc/migrating-a-plugin.md).


# Entry Points

Each package contains a single plugin.
The keys within the entry points section describe the sort of plugin thats available:
  - `idapython` for IDAPython-based plugins
  - target triple for compiled plugins, like `aarch64-apple-darwin`

## Examples

For a single Python file named `hello.py` (like above):

```toml
[project.entry-points.'idapro.plugins']
idapython = 'hello'  # note: there's no file extension
```

For a plugin within a larger Python package, such as for the default plugin
provided by capa in [capa.ida.plugin](https://github.com/mandiant/capa/blob/master/capa/ida/plugin/__init__.py):

```toml
[project.entry-points.'idapro.plugins']
idapython = 'capa.ida.plugin'
```

In this scenario, the entry point section would be in capa's `pyproject.toml`,
so you'd install `capa` within your IDAPython virtualenv and the plugin would
now be available within IDA.

Since the name `capa` doesn't match the `idapro-plugin-*` prefix for IDA plugins
available on PyPI, it would have to be registered with the extras list.

### Native plugins

For a compiled plugin, create a Python package with the compiled artifacts stored within the "Python" package:

```sh
❯ eza --tree --level=2 --long --git
native-ida-plugin
├── bin
│   └── native_ida_plugin
│       ├── __init__.py
│       ├── mysample.so
│       ├── mysample.dll
│       ├── mysample_aarch64.dylib
│       └── mysample_x86_64.dylib
├── pyproject.toml
└── README.md
```

And use target triple names as the entry point keys to specify filenames for the compiled artifacts:

```toml
[project.entry-points.'idapro.plugins']
aarch64-apple-darwin = "native_ida_plugin:mysample_aarch64"  # note: extensions are automatically appended
x86_64-apple-darwin  = "native_ida_plugin:mysample_x86_64"
x86_64-unknown-linux = "native_ida_plugin:mysample"
x86_64-pc-windows    = "native_ida_plugin:mysample"

[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[tool.setuptools]
package-dir = {"" = "bin"}  # Python package data is found in "bin/" directory.
                            # "src/" is the default, but we'll use "bin/" for all this binary data.

[tool.setuptools.package-data]
"native_ida_plugin" = [
    # filenames relative to: bin/native_ida_plugin/
    "mysample.*",
    "mysample_aarch64.*",
    "mysample_x86_64.*",
]
```

Unfortunately the entry point value (`native_ida_plugin:mysample_aarch64`) cannot contain `/` or `.`,
 so the compiled artifacts are best placed in that package root directory.
Its also possible to use a layout like `native_ida_plugin.aarch64:mysample`.

Technically, the entry point value is supposed to point to a Python object.
We abuse this a bit, because we assign a specific meaning to entry point keys like `aarch64-apple-darwin`.
To make this safe, add package level variables to `bin/native_ida_plugin/__init__.py`:

```py
mysample_aarch64 = None
mysample_x86_64 = None
mysample = None
```

But this is not strictly necessary today.

# Native Dependencies

(this is experimental/not implemented yet/just an idea)

Extend the search path for libraries like this:

```toml
[tool.idapro.plugins.lib]
'aarch64-apple-darwin' = 'lib/darwin-aarch64/'
'x86_64-apple-darwin'  = 'lib/darwin-x86_64/'
```

Which is useful if your plugin depends on additional native libraries; for example, OpenSSL.
