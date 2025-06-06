# As an IDA Pro Plugin Author

The IDA Pro Plugin Manager is a tool to help you distribute your IDA Pro plugins so that users can easily discover, install, and manage them.
It defines a few formats and conventions so that everyone can interoperate with a central index.

The requirements for this system are enumerated in [here](https://docs.google.com/document/d/1FaDLzOhxOTedhOh8LH9fpe3dqvjFaH6Cat9IGmtQw6o/edit?usp=sharing), 
and a design document is [here](https://docs.google.com/document/d/1jhuxSbFfacc2IRbjSNf1MNYfA7tBKhYWnZvIZpiJkLo/edit?usp=sharing).
Check out those docs for more details and rationale. 

Anyways, here's what you need to know to get started...

## Packaging Plugins

Plugins are distributed via PyPI, which is usually (but not always) used for Python packages.
We use Python-style metadata, such as a `pyproject.toml` file, to describe the plugin.
This *doesn't mean your plugin has to be written in Python*, its just the infrastructure and file format format we use.
Check out the [design doc](https://docs.google.com/document/d/1jhuxSbFfacc2IRbjSNf1MNYfA7tBKhYWnZvIZpiJkLo/edit?usp=sharing) for more detail.

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
name = "williballenthin-basic-ida-plugin"
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
 and find plugins via the metadata, including `williballenthin-basic-ida-plugin`.

I packaged this plugin and uploaded it to PyPI, so you can install it like this:

    ippm install williballenthin-basic-ida-plugin

but you can also install it using `pip` directly:

    pip install williballenthin-basic-ida-plugin

If you have a local plugin in development, you can use other Python idioms, like:

    pip install --editable /path/to/basic-ida-plugin/source

There is a more comprehensive miration guide found in [doc/migrating-a-plugin.md](doc/migrating-a-plugin.md).


## Entry Points

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
