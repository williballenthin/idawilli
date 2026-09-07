# Memloader specification

Memloader is an IDA plugin that installs two file loaders. Both bring bytes into an IDA database without writing the analyzed file to disk. This document describes the behavior a user sees. The implementation is described in [design.md](design.md).

## Loaders

**Memloader ZIP** accepts any file that starts with a ZIP local header or end-of-central-directory signature and contains at least one non-directory member. It offers itself under the format name `Memloader ZIP`, alongside IDA's own archive loader. When chosen, it selects one member, extracts it in memory, and loads those bytes with IDA's regular file format loaders. The database is named after the member (`sample.exe` inside `x.zip` gives `sample.exe.i64` next to `x.zip`).

**Memloader URL** offers itself for any input file under the format name `Memloader URL`. When chosen, it downloads a URL and loads the downloaded bytes; the input file is ignored. The database is named after the SHA-256 hex digest of the downloaded bytes. The download uses a browser-like user agent and a 60 second timeout.

Both loaders share the same loading pipeline:

1. IDA's loaders are asked to recognize the bytes. The best candidate is used with the same flags IDA would apply to a file on disk, so loader name, file hashes, compiler and type library detection are recorded as usual.
2. When the best candidate is itself an archive loader, loading fails with a message that nested archives are not supported. Extracting an archive from an archive is out of scope.
3. When no loader recognizes the bytes, the bytes are loaded as x86 shellcode: processor `metapc`, one code segment named `shellcode` from address 0, entry point `start` at 0. In interactive mode the user confirms this and chooses 32-bit or 64-bit. In batch mode the `bitness` option decides, defaulting to 32-bit.

## Interactive mode

The ZIP loader shows a modal chooser with the member name, size and encryption flag when the archive has more than one member. With one member the chooser is skipped. For an encrypted member it asks for a password, prefilled with `infected`, the usual convention for malware archives. A wrong password fails the load with a message. Cancelling any prompt aborts the load.

The URL loader asks for the URL in a text prompt. If a database with the target name already exists next to the input file, the user is asked before it is overwritten.

## Batch mode

In batch mode (`idat`, idalib) no prompts are shown. The loader is selected with IDA's `-T` switch, for example `-T"Memloader ZIP"`, because IDA's built-in archive loader otherwise wins for ZIP files. Options come from `-Omemloader:` as `key=value` pairs separated by `;`:

| Option     | Meaning                                              | Default    |
|------------|------------------------------------------------------|------------|
| `member`   | ZIP member to load, matched by full path or basename | first file |
| `password` | Password for encrypted members                       | `infected` |
| `url`      | URL to download (URL loader)                         | none       |
| `bitness`  | `32` or `64` for the shellcode fallback              | `32`       |

The separator is `;` rather than `:` so that URLs can be passed unescaped. Unknown keys, entries without `=`, and a bitness other than 32 or 64 are rejected.

Without a `url` option the URL loader does not offer itself in batch mode, so ordinary files load with their normal loader. In batch mode the database keeps the path IDA chose for the input file; it is not renamed after the member or hash, because the caller controls output paths.

## Installation and discovery

The plugin is distributed through the IDA Plugin Manager and installs into the user plugin directory. IDA only scans `loaders/` directories for loaders, so every time IDA starts the plugin creates two symbolic links, `memloader_zip_loader.py` and `memloader_url_loader.py`, in `$IDAUSR/loaders/`. Each link points at the entry file with the same name in the `loaders/` directory of the plugin.

Links are used rather than copies or generated files so that a loader entry always names the plugin it belongs to, also after the plugin has been removed. Links that already point at the right target are left alone. Links into the plugin that are no longer expected, dangling `memloader_*.py` links, and generated stub files from earlier versions are removed. Files not created by Memloader are never touched.

On Windows, symbolic links need Developer Mode or an elevated IDA. When the symbolic link is refused, the plugin makes a hard link instead, which any user can create on the same NTFS volume. A hard link does not record the plugin path, and after an upgrade replaces the plugin files it keeps the previous entry file until the plugin relinks it at the next start. The entry files are small forwarders whose content rarely changes, so the previous version keeps working in between.

IDA, `idat` and idalib all load plugins before the input file is opened, so the loaders are available from the first run after installation. After uninstalling the plugin, the links remain. IDA ignores a dangling symbolic link without a message, so the loaders disappear from the loader list and nothing else changes. On Windows, where a hard link was made instead, the entry file survives. When it cannot import the removed package, it stays inert, accepts no file, and prints one message in the IDA output window each time the loader list is built. The message names the file to delete.

## Supported versions

IDA 9.2 and later. idalib in IDA 9.0 and 9.1 does not accept the `-T` switch, so the headless tests cannot run there and those versions are not declared as supported.
