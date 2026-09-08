# vtloader design

## Layout

```
ida-plugin.json         Plugin Manager manifest; this directory is the plugin root
vtloader_entry.py       PLUGIN_FIX plugin: keeps the loader link current, VirusTotal menu entry
loaders/
  vtloader_loader.py    Loader entry file that $IDAUSR/loaders/ links to
vtloader/
  options.py            LoadOptions parsed from -Ovtloader:
  virustotal.py         VirusTotal API client (urllib)
  settings.py           Plugin settings read through ida-settings
  install.py            Creation and maintenance of the loader link
  instance.py           Launching a second IDA instance for a hash
  kernel.py             ctypes bridge to the IDA kernel loader functions
  core.py               The loading pipeline
  loader.py             accept_file / load_file
tests/                  pytest suite, pure Python plus in-process idalib
```

`options.py`, `virustotal.py`, `install.py` and `instance.py` do not import IDA modules, so they are tested without IDA.

## Plugin and link

`vtloader_entry.py` is a `PLUGIN_FIX | PLUGIN_MULTI` plugin. Its `plugmod_t` constructor calls `install_loader_links` with `$IDAUSR/loaders` and the plugin root, which is the directory of the plugin file. IDA, `idat` and idalib load plugins at startup, before the loader list is built for the input file, so the link is available from the first session after installation.

IDA only scans `loaders/` directories for loader modules, which is why the link exists at all. `create_link` tries the kinds in `DEFAULT_LINK_KINDS` in order: a symbolic link everywhere, then a hard link on Windows, where symbolic links need Developer Mode or elevation. A link is current when it is a symlink with the right target or a hard link of the target (`os.path.samefile`).

`remove_retired_links` runs first and deletes any other loader-named file that is ours, under either the `vtloader_` prefix or the `memloader_` one this plugin used up to version 1.1: that plugin's ZIP, URL and VirusTotal links, links left behind when the plugin root moves, dangling symlinks, and generated stub files. Ours is recognised by the symlink target, by `samefile`, or by the first line of the file, which is the entry file docstring under either name or the old stub marker. A live link into some other plugin's directory is left alone, as is any file that is not ours. `remove_loader_links` deletes only links into a given plugin root.

Neither the plugin nor the entry file modifies `sys.path`. IDA adds every plugin directory that holds an `ida-plugin.json` to `sys.path` when it loads plugins, so `vtloader` imports as a regular package from both. The entry file imports the loader module and defines `accept_file` and `load_file` wrappers that forward the call. When the import raises `ModuleNotFoundError` for `vtloader` — the case of a hard link that outlived the plugin — the entry file prints a message through `ida_kernwin.msg` naming its own path under `$IDAUSR/loaders`, and `accept_file` returns 0. Other import errors propagate.

The wrappers are defined in the entry file rather than imported: the IDA kernel runs a script loader's function with the loader module's namespace as the function's globals, so a function imported from another module would fail with `NameError` on its own module-level names.

## Kernel bridge

IDAPython does not export `build_loaders_list`, `load_nonbinary_file`, `free_loaders_list`, or the byte-array form of `create_bytearray_linput`. `kernel.py` binds them with `ctypes` from the kernel library in the IDA install directory: `libida.dylib`, `libida.so` or `ida.dll`, with the `ida32` variant when `BADADDR` is 32-bit. `_load_info_t` mirrors the C++ `load_info_t` layout (linked list `next`, `qstring` fields for the loader file, format name and processor, then `ftype`, `loader_flags`, `lflags`, `pri`). `LoaderInfo` is a frozen dataclass snapshot of one entry; `LoaderList.best` is the first entry, which the kernel orders by priority.

`IdaKernel` exposes two context managers, `bytearray_linput` and `loaders_list`, that own the native objects and free them on exit, and `load_nonbinary_file`, which runs the chosen loader against the in-memory input.

## Loading pipeline

`core.load_buffer_into_ida(buffer, filename, neflags, options, database_dir)` is called from inside the loader's `load_file`, so a database is already open and the outer loader owns the load.

1. An empty buffer is a `LoadError`.
2. `set_database_names` sets the root filename to the hash. Interactively it also moves the database into `database_dir`, asking before overwriting; in batch mode the path IDA chose is kept.
3. The buffer becomes a byte-array `linput_t` and the loader list is built for it.
4. No candidates: `confirm_shellcode_fallback` decides the bitness (prompt or option) and `load_as_shellcode` sets `metapc`, the application bitness, one `CODE` segment named `shellcode` at 0, copies the bytes with `mem2base`, and adds the `start` entry.
5. A best candidate with the archive flag is rejected: vtloader cannot open archives in memory.
6. Otherwise the database file type is set the way IDA's file dialog would (`f_LOADER` for script loaders reporting 1, the loader's type otherwise) and `load_nonbinary_file` runs the candidate with the outer `neflags`. `NEF_FIRST` in those flags makes the kernel record the loader name, hashes and size, then run compiler and type library detection for the loaded bytes.

The shellcode path leaves the file type as `f_LOADER`. Setting `f_BIN` makes IDA's post-load handling for binary files re-apply its own bitness, which undoes the 32-bit choice.

## Loader

`loader.accept_file` returns 0 in batch mode when no `sha256` option is present, and the format name otherwise, so an ordinary file still loads normally when the loader was not asked for. `load_file` obtains the hash (option or `ask_str`), downloads it with the key from the plugin settings, and calls `load_buffer_into_ida` under the hash name with the Downloads directory.

`load_file` returns 1 on success and lets exceptions propagate; the kernel turns an exception into a warning and a failed load, which is the desired outcome for cancelled prompts, a missing API key and download errors.

Options are read with `ida_loader.get_plugin_options("vtloader")` and parsed by `LoadOptions.from_plugin_options`. Batch mode is `ida_kernwin.cvar.batch`.

## VirusTotal and the second instance

`virustotal.py` asks the API for a short-lived download URL, fetches it, and verifies the bytes against the requested hash. API errors are mapped to messages naming the likely cause (bad key, no download privilege, unknown file, exhausted quota).

The plugin's menu entry checks the hash before starting anything, then launches a second IDA instance with `-T` to select the loader, `-O` to pass the hash and `-o` to place the database, against a small temporary input file whose content the loader ignores. IDA reads a 16-byte block of that input while initialising, which is why the file exists at all; naming it after the hash gives IDA a meaningful input name in the meantime.

## Tests

`tests/conftest.py` locates an IDA installation from `IDADIR` or `~/.idapro/ida-config.json` (appending `Contents/MacOS` for a macOS app bundle), creates a temporary `IDAUSR` with the license files and a `plugins/vtloader` symlink to the plugin directory, and exports both variables before `idapro` is imported. The plugin then runs at `import idapro` and creates the loader link itself. One test starts a separate idalib process with only these variables set, which proves that the installed plugin alone makes the loader importable. Another hard links the entry file into an IDAUSR without the plugin and checks that a plain PE still loads, no traceback appears, and the cleanup message names the file. The `ida` fixture imports `idapro`, accepts the EULA through the registry, and skips when no installation is available or the IDA SDK version is older than 9.2; idalib in 9.1 exits the process on the `-T` switch and idalib in 9.0 ignores `-O` options.

`open_database` is a context manager around `idapro.open_database` and `close_database`. idalib keeps `-O` options from earlier opens in the same process, so the fixture appends an empty `-Ovtloader:` when the caller passes none.

Tests that must not touch the network replace `loader.fetch`, which is the single seam between the API client and the pipeline. `tests/pe.py` builds a 1 KiB PE32 with one `.text` section that IDA's PE loader accepts; `tests/data/pma-lab01-01.zip` supplies real sample bytes for the tests that check a genuine PE loads and that a live download matches its hash.
