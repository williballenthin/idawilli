# IDA Pro Plugin Manager


## Installation

There are two steps:

  1. to fetch the plugin manager
  2. to register the plugin manager with IDA Pro

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

Copy `plugins/load_idapro_plugin_manager.py` to `~/.idapro/plugins/`.

You only have to do this once, even if you upgrade IDA.

## Packaging Plugins

Plugins are distributed via PyPI, which is usually (but not always) used for Python packages.
We use Python-style metadata, such as a `pyproject.toml` file, to describe the plugin. 

By adding an "entry point" for the `idapro.plugins` group,
we can register a plugin with the IDA Pro Plugin Manager.

For example, consider a simple IDA plugin with a single file: `hello.py`. 
(Recall that IDAPython plugins should have a function named `PLUGIN_ENTRY` that's used to initialize the plugin.)

The package structure would look like:

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
