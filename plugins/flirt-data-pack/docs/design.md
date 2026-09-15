# flirt-data-pack design

## Layout

```
ida-plugin.json               Plugin Manager manifest; this directory is the plugin root
flirt_data_pack_entry.py       PLUGIN_FIX plugin: keeps sig links current, hooks loader_finished
flirt_data_pack/
  apply.py                     File-type-to-signature mapping and auto-apply logic
  install.py                   Creation and maintenance of sig file symlinks
  sig.py                       Minimal FLIRT signature builder for testing
sigs/
  pc/
    dummy.sig                  Dummy zero-function signature for testing
tests/                         pytest suite, pure Python plus in-process idalib
```

`apply.py`, `install.py` and `sig.py` do not import IDA modules, so they are tested without IDA.

## Plugin and links

`flirt_data_pack_entry.py` is a `PLUGIN_FIX | PLUGIN_MULTI` plugin. Its `plugmod_t` constructor calls `install_sig_links` for each processor directory under `sigs/`, targeting `$IDAUSR/sig/<proc>/`. IDA loads plugins at startup before analysis begins, so the signatures are available from the first session after installation.

IDA's `find_files()` and the "Apply FLIRT signature" dialog both scan `$IDAUSR/sig/<proc>/` flat without recursing into subdirectories. Each `.sig` file must sit directly in that directory. To avoid collisions between plugins that ship signatures with the same name, every link is prefixed with `flirt_data_pack_`: `sigs/pc/dummy.sig` becomes `~/.idapro/sig/pc/flirt_data_pack_dummy.sig`.

`remove_stale_links` runs before installation and deletes any prefixed dangling symlink, covering the case where a signature was removed from the plugin between versions.

Ownership is determined by the link name prefix (`flirt_data_pack_`) combined with the symlink target resolving into the plugin root. Links without the prefix, or pointing into a different plugin, are left alone. Any prefixed symlink is replaceable regardless of where it points, so a moved plugin root is handled by relinking rather than leaving stale entries. Path comparisons use `resolve()` rather than raw `readlink` output so that extended-length paths on Windows (``\\?\…``) compare correctly.

## Auto-apply

The `plugmod_t` constructor installs an `IDB_Hooks` instance that listens for `loader_finished`. When a file finishes loading, the hook reads the file type from `ida_ida.inf_get_filetype()` and looks it up in `AUTO_APPLY`, a dict mapping file type constants to lists of signature base names. Each matching base name is prefixed with `flirt_data_pack_` and passed to `ida_funcs.plan_to_apply_idasgn()`.

The processor is not checked in the mapping. IDA searches `sig/<current_proc>/` automatically, so a signature shipped only under `sigs/pc/` is never found when the active processor is ARM. This means the directory layout under `sigs/` is the only thing that controls processor filtering.

The hooks are unhooked when the `plugmod_t` is garbage collected.

## The dummy signature

`sigs/pc/dummy.sig` is a valid FLIRT header (magic `IDASGN`, version 10, METAPC processor) with zero functions. It exercises the installation and auto-apply mechanism without providing real matches. `sig.py` can build these programmatically for tests.

## Tests

`tests/conftest.py` locates an IDA installation from `IDADIR` or `~/.idapro/ida-config.json`, creates a temporary `IDAUSR` with the license files and a `plugins/flirt-data-pack` symlink to the plugin directory, and exports both variables before `idapro` is imported. The `ida` fixture imports `idapro`, accepts the EULA, and skips when no installation is available.

The install tests verify symlinking, idempotency, retargeting when the plugin root moves, hard link fallback, stale link cleanup, and refusal to overwrite foreign files. `TestRealPlugin` checks that the shipped `dummy.sig` has the right magic and can be installed into a temporary directory. The apply tests verify the mapping logic and name prefixing without IDA.
