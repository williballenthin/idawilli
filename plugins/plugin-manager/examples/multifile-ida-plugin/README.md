# multifile-ida-plugin

An example IDA plugin that uses multiple files.

```
 multifile-ida-plugin
 ├── pyproject.toml
 ├── README.md
 └── src
     └── multifile_ida_plugin
         ├── __init__.py
         └── plugin
             └── __init__.py
```

There is a library `multifile_ida_plugin` with arbitrary code
 (in this case, a function `multifile_ida_plugin.hello`).

```py
def hello():
  print("hello from Python (multifile)")
```

Then, there's an IDA plugin found in `multifile_ida_plugin.plugin`
 which corresponds to the file `src/multifile_ida_plugin/plugin/__init__.py`
 and contains the `PLUGIN_ENTRY` function expected by IDA.


```py
import idaapi
import multifile_ida_plugin

class multifile_plugmod_t(idaapi.plugmod_t):
    def run(self, arg):
        multifile_ida_plugin.hello()
        return 0

class multifile_plugin_t(idaapi.plugin_t):
    ...
    def init(self):
        return multifile_plugmod_t()


def PLUGIN_ENTRY():
    return multifile_plugin_t()
```

The plugin invokes a routine from the library code, demonstrating how not all of the plugin code
 has to be bundled into the primary plugin file.

The `pyproject.toml` shows how to specify the location of the plugin:

```toml
[project.entry-points.'idapro.plugins']
idapython = "multifile_ida_plugin.plugin"
```

## publishing

Published to PyPI as [multifile-ida-plugin](https://pypi.org/project/multifile-ida-plugin/) via the GH Action workflow [publish-multifile-ida-plugin.yml](/.github/workflows/publish-multifile-ida-plugin.yml).

