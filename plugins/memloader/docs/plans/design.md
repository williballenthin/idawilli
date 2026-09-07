# Memloader design

This document describes how the code implements the behavior in [spec.md](spec.md).

## Layout

```
ida-plugin.json            Plugin Manager manifest; this directory is the plugin root
memloader_entry.py        PLUGIN_FIX plugin, creates the loader links at IDA startup
loaders/                   Loader entry files that $IDAUSR/loaders/ links to
memloader/
  options.py               LoadOptions parsed from -Omemloader:
  archive.py               ZIP inspection and in-memory extraction (zipfile)
  download.py              URL download and SHA-256 naming (urllib)
  install.py               Creation and maintenance of the loader links
  kernel.py                ctypes bridge to the IDA kernel loader functions
  core.py                  Shared loading pipeline used by both loaders
  loaders/zip_loader.py    accept_file / load_file for ZIP archives
  loaders/url_loader.py    accept_file / load_file for URLs
tests/                     pytest suite, pure Python plus in-process idalib
```

`options.py`, `archive.py`, `download.py` and `install.py` do not import IDA modules, so they are tested without IDA.

## Plugin and links

`memloader_entry.py` is a `PLUGIN_FIX | PLUGIN_HIDE | PLUGIN_MULTI` plugin. Its `plugmod_t` constructor calls `install_loader_links` with `$IDAUSR/loaders` and the plugin root, which is the directory of the plugin file. IDA, `idat` and idalib load plugins at startup, before the loader list is built for the input file, so the links are available from the first session after installation.

`install_loader_links` creates one link per `LoaderLink` in `LINKS`, named `memloader_<name>.py` and pointing at `<plugin root>/loaders/memloader_<name>.py`. `create_link` tries the kinds in `DEFAULT_LINK_KINDS` in order: a symbolic link everywhere, then a hard link on Windows, where symbolic links need Developer Mode or elevation. A link is current when it is a symlink with the right target or a hard link of the target (`os.path.samefile`). A link with another target, a hard link left behind by a replaced target, and a generated stub file from an earlier version are replaced; the last two are recognized by the first line of the file, which is the entry file docstring or the old stub marker. Before that, `memloader_*.py` links that point into the plugin root but are not expected, and dangling `memloader_*.py` links, are removed. Any other file with a `memloader_` name is left alone with a warning. `remove_loader_links` deletes only links into the given plugin root.

Neither the plugin nor the entry files modify `sys.path`. IDA adds every plugin directory that holds an `ida-plugin.json` to `sys.path` when it loads plugins, so `memloader` imports as a regular package from the plugin file and from the linked entry files. Each entry file imports its loader module and defines `accept_file` and `load_file` wrappers that forward the call. When the import raises `ModuleNotFoundError` for `memloader`, the case of a hard link that outlived the plugin, the entry file prints a message through `ida_kernwin.msg` that names its own path under `$IDAUSR/loaders`, and `accept_file` returns 0. Other import errors propagate. The wrappers are defined in the entry file rather than imported: the IDA kernel runs a script loader's function with the loader module's namespace as the function's globals, so a function imported from another module would fail with `NameError` on its own module-level names.

## Kernel bridge

IDAPython does not export `build_loaders_list`, `load_nonbinary_file`, `free_loaders_list`, or the byte-array form of `create_bytearray_linput`. `kernel.py` binds them with `ctypes` from the kernel library in the IDA install directory: `libida.dylib`, `libida.so` or `ida.dll`, with the `ida32` variant when `BADADDR` is 32-bit. `_load_info_t` mirrors the C++ `load_info_t` layout (linked list `next`, `qstring` fields for the loader file, format name and processor, then `ftype`, `loader_flags`, `lflags`, `pri`). `LoaderInfo` is a frozen dataclass snapshot of one entry; `LoaderList.best` is the first entry, which the kernel orders by priority.

`IdaKernel` exposes two context managers, `bytearray_linput` and `loaders_list`, that own the native objects and free them on exit, and `load_nonbinary_file`, which runs the chosen loader against the in-memory input.

## Loading pipeline

`core.load_buffer_into_ida(buffer, filename, neflags, options)` is called from inside a loader's `load_file`, so a database is already open and the outer loader owns the load.

1. An empty buffer is a `LoadError`.
2. `set_database_names` sets the root filename to the member or hash name. Interactively it also moves the database path next to the input file, asking before overwriting; in batch mode the path IDA chose is kept.
3. The buffer becomes a byte-array `linput_t` and the loader list is built for it.
4. No candidates: `confirm_shellcode_fallback` decides the bitness (prompt or option) and `load_as_shellcode` sets `metapc`, the application bitness, one `CODE` segment named `shellcode` at 0, copies the bytes with `mem2base`, and adds the `start` entry.
5. A best candidate with the archive flag is rejected as a nested archive.
6. Otherwise the database file type is set the way IDA's file dialog would (`f_LOADER` for script loaders reporting 1, the loader's type otherwise) and `load_nonbinary_file` runs the candidate with the outer `neflags`. `NEF_FIRST` in those flags makes the kernel record the loader name, hashes and size, then run compiler and type library detection for the loaded bytes.

The shellcode path leaves the file type as `f_LOADER`. Setting `f_BIN` makes IDA's post-load handling for binary files re-apply its own bitness, which undoes the 32-bit choice.

## Loaders

`zip_loader.accept_file` checks the ZIP magic, lists members with `archive.get_members`, and returns the format name when at least one member exists. `load_file` reads the whole input, chooses a member (`choose_member`: explicit option or first member in batch mode, single member directly, otherwise a modal `ida_kernwin.Choose`), obtains a password when the member is encrypted (`choose_password`: option in batch mode, otherwise `ask_str` prefilled with the default), extracts it, and calls `load_buffer_into_ida` with the member's basename.

`url_loader.accept_file` returns 0 in batch mode when no `url` option is present and the format name otherwise. `load_file` obtains the URL (option or `ask_str`), downloads it, and loads the bytes under the SHA-256 name.

Both `load_file` functions return 1 on success and let exceptions propagate; the kernel turns an exception into a warning and a failed load, which is the desired outcome for cancelled prompts, bad passwords and download errors.

Options are read with `ida_loader.get_plugin_options("memloader")` and parsed by `LoadOptions.from_plugin_options`. Batch mode is `ida_kernwin.cvar.batch`.

## Tests

`tests/conftest.py` locates an IDA installation from `IDADIR` or `~/.idapro/ida-config.json` (appending `Contents/MacOS` for a macOS app bundle), creates a temporary `IDAUSR` with the license files and a `plugins/memloader` symlink to the repository, and exports both variables before `idapro` is imported. The plugin then runs at `import idapro` and creates the loader links itself. One test starts a separate idalib process with only these variables set and loads a PE from a ZIP, which proves that the installed plugin alone makes the loaders importable. Another hard links the entry files into an IDAUSR without the plugin and checks that a plain PE still loads, no traceback appears, and the cleanup message names both files. The `ida` fixture imports `idapro`, accepts the EULA through the registry, and skips when no installation is available or the IDA SDK version is older than 9.2. Tests run against IDA 9.2, 9.3 and 9.4; idalib in 9.1 exits the process on the `-T` switch and idalib in 9.0 ignores `-O` options.

`open_database` is a context manager around `idapro.open_database` and `close_database`. idalib keeps `-O` options from earlier opens in the same process, so the fixture appends an empty `-Omemloader:` when the caller passes none. Loader tests pass `-T"Memloader ZIP"` or `-T"Memloader URL"` because the built-in archive loader otherwise wins in batch mode.

Fixtures are hermetic: `tests/pe.py` builds a 1 KiB PE32 with one `.text` section that IDA's PE loader accepts, `tests/zipcrypto.py` writes ZipCrypto-encrypted archives (the standard library only reads them), and `http_server` serves a temporary directory on a loopback port for the URL loader.
