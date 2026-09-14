# vtloader

vtloader downloads a file from VirusTotal by its SHA-256 and loads it into IDA without writing the sample to a separate file.

The data goes to IDA's normal file loaders, so IDA writes only its database for the sample. This can avoid an on-access antivirus scan. If IDA cannot identify the format, vtloader can load the data as raw x86 shellcode at address 0.

This project began as a Python port of the C++ Memloader plugin by [Kasif Dekel](https://twitter.com/kasifdekel) at SentinelLabs.

## Install

vtloader requires IDA 9.2 or later.

```sh
hcli plugin install vtloader
```

Downloads require an API key with file download access. Set the key in the vtloader plugin settings. You can also set it from the command line:

```sh
hcli plugin config set vtloader vt_api_key YOUR_API_KEY
```

## Use vtloader in IDA

Select **Edit > Plugins > vtloader: load from VirusTotal** and enter a SHA-256. vtloader checks the hash against VirusTotal and starts a new IDA instance to load it. To use the current instance instead, open any file and select **vtloader** in the loader list; the opened file is ignored and vtloader asks for the hash.

Either way the database is named after the hash and written to `~/Downloads`.

If IDA cannot identify the downloaded data, vtloader asks whether to load it as 32-bit or 64-bit shellcode. vtloader cannot open archives in memory; a download that is itself an archive is reported rather than loaded.

## Use without the UI

The loader works with `idat` and idalib. Select it with `-T` and pass the hash with `-Ovtloader:`.

```sh
idat -A -T"vtloader" '-Ovtloader:sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' placeholder.bin
idat -A -T"vtloader" '-Ovtloader:sha256=...;bitness=64' placeholder.bin
```

| Option | Use | Default |
|---|---|---|
| `sha256` | SHA-256 hash of the file to download | Required in batch mode |
| `bitness` | Shellcode bitness: `32` or `64` | `32` |

Separate options with `;`. The input file must exist but its content is ignored. Without `sha256` the loader does not claim the input at all, so ordinary files still load normally. IDA keeps the database path that the caller selects.

## Loader link

When IDA starts, vtloader links `vtloader_loader.py` into the user `loaders/` directory, because IDA only scans that directory for loader modules. The link points at the plugin directory, and vtloader refreshes it the next time IDA starts.

This plugin was called Memloader up to version 1.1 and installed ZIP and URL loaders as well. Its three links are removed on the first start after upgrading, so uninstall `memloader` and IDA will stop offering them.

On Windows, symbolic links require Developer Mode or an elevated IDA process. vtloader uses hard links if needed. After uninstall, you can safely delete any remaining link. IDA ignores broken symbolic links. A remaining hard link prints the path that you must delete.

## Develop

vtloader lives in the [idawilli](https://github.com/williballenthin/idawilli) repository under `plugins/vtloader`. Run the tests from the repository root:

```sh
uv run --with idapro --with ida-settings --with pytest \
    pytest plugins/vtloader/tests -v
uvx --with ida-hcli hcli plugin install -e plugins/vtloader
```

The pure Python tests run on any system. The idalib tests require IDA in `IDADIR` or `~/.idapro/ida-config.json`. Live VirusTotal tests also require `VT_API_KEY`. Pytest skips tests that cannot run.

`plugins/vtloader/tests/data/pma-lab01-01.zip` contains the Lab 01-01 EXE and DLL from *Practical Malware Analysis*, which the tests use as known sample bytes. The password is `infected`.
