# Memloader

Memloader loads files into IDA without writing the loaded sample to a separate file. It provides three loaders:

- **Memloader ZIP** extracts one file from a ZIP archive.
- **Memloader URL** downloads a file from a URL.
- **Memloader VirusTotal** downloads a file by its SHA-256 hash.

Each loader passes the data to IDA's normal file loaders. IDA writes only its database for the sample. This can avoid an on-access antivirus scan. If IDA cannot identify the format, Memloader can load the data as raw x86 shellcode at address 0.

This project is a Python port of the C++ Memloader plugin by [Kasif Dekel](https://twitter.com/kasifdekel) at SentinelLabs.

## Install

Memloader requires IDA 9.2 or later.

```sh
hcli plugin install memloader
```

VirusTotal downloads require an API key with file download access. Set the key in the Memloader plugin settings. You can also set it from the command line:

```sh
hcli plugin config set memloader vt_api_key YOUR_API_KEY
```

## Use Memloader in IDA

| Loader | Start it | Database |
|---|---|---|
| ZIP | Open the ZIP and select **Memloader ZIP** | Member name; next to the ZIP |
| URL | Open any file and select **Memloader URL** | SHA-256; next to the opened file |
| VirusTotal | Select **Edit > Plugins > Memloader: load from VirusTotal** | SHA-256; in `~/Downloads` |

For a ZIP, select a member if the archive contains more than one. Enter a password if the member is encrypted. The default is `infected`.

The URL loader ignores the opened file and asks for a URL. The VirusTotal command asks for a SHA-256 hash and starts a new IDA instance. To use the current instance, open any file and select **Memloader VirusTotal**. Both VirusTotal methods put the database in `~/Downloads`.

If IDA cannot identify the data, Memloader asks if you want to load it as 32-bit or 64-bit shellcode. Memloader does not load nested archives.

## Use without the UI

The loaders work with `idat` and idalib. Select a loader with `-T`. Set options with `-Omemloader:`. Separate options with a semicolon.

```sh
idat -A -T"Memloader ZIP" '-Omemloader:member=payload.exe;password=s3cret' sample.zip
idat -A -T"Memloader URL" '-Omemloader:url=https://example.com/sample.bin' placeholder.bin
idat -A -T"Memloader VirusTotal" '-Omemloader:sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' placeholder.bin
idat -A -T"Memloader ZIP" '-Omemloader:bitness=64' shellcode.zip
```

| Option | Use | Default |
|---|---|---|
| `member` | ZIP file name or path | First file |
| `password` | Password for an encrypted ZIP file | `infected` |
| `url` | URL for the URL loader | Not set |
| `sha256` | SHA-256 hash for the VirusTotal loader | Not set |
| `bitness` | Shellcode bitness: `32` or `64` | `32` |

For a ZIP, use `-T` or IDA will use its own archive loader. The URL and VirusTotal loaders require `url` or `sha256` in batch mode. IDA keeps the database path that the caller selects.

## Loader links

When IDA starts, Memloader links these files into the user `loaders/` directory:

- `memloader_zip_loader.py`
- `memloader_url_loader.py`
- `memloader_vt_loader.py`

The links point to the plugin directory. Memloader updates them the next time IDA starts.

On Windows, symbolic links require Developer Mode or an elevated IDA process. Memloader uses hard links if needed. After uninstall, you can safely delete any remaining links. IDA ignores broken symbolic links. A remaining hard link prints the path that you must delete.

## Develop

Memloader lives in the [idawilli](https://github.com/williballenthin/idawilli) repository under `plugins/memloader`. Run the tests from the repository root:

```sh
uv run --with idapro --with ida-settings --with pytest \
    pytest plugins/memloader/tests -v
uvx --with ida-hcli hcli plugin install -e plugins/memloader
```

The pure Python tests run on any system. The idalib tests require IDA in `IDADIR` or `~/.idapro/ida-config.json`. Live VirusTotal tests also require `VT_API_KEY`. Pytest skips tests that cannot run.

`plugins/memloader/tests/data/pma-lab01-01.zip` contains the Lab 01-01 EXE and DLL from *Practical Malware Analysis*. The password is `infected`. You can use these files to try the plugin.
