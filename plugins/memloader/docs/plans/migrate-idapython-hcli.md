# Memloader Migration: IdaPython + Plugin Manager

## Context

Memloader is a native C++ IDA loader suite (3 DLLs) that loads binaries into IDA from ZIP files or URLs without writing to disk. It implements the `loader_t` interface, which participates in IDA's file-open pipeline. The goal is to rewrite it in IdaPython so it's cross-platform, easier to maintain, and distributable via the IDA Plugin Manager (HCLI).

IDA only discovers loaders from its `loaders/` directory and there's no runtime API to register a loader from elsewhere. The workaround: a `PLUGIN_FIX` plugin that creates symlinks from `$IDAUSR/loaders/` into the plugin's own directory, so IDA finds the Python loaders when a user opens a file.

## Architecture

Two components, one package:

**1. The Plugin (`memloader_entry.py`)** — `plugin_t` with `PLUGIN_FIX`
- `init()` runs at IDA startup, before any file is opened
- Creates symlinks from `$IDAUSR/loaders/` to the loader .py files owned by this plugin
- On each startup, removes stale dangling symlinks but leaves working ones alone
- Symlinks persist across IDA exits (other IDA instances may be using them)

**2. The Loaders (`memloader/loaders/zip_loader.py`, `memloader/loaders/url_loader.py`)** — standalone Python files with `accept_file()` + `load_file()`
- Uses Python stdlib for ZIP (`zipfile`), HTTP (`urllib.request`), and hashing (`hashlib`)
- Delegates to IDA's built-in loaders via `ida_loader.build_loaders_list()` + `ida_loader.load_nonbinary_file()`
- Falls back to shellcode mode if no loader matches

## Package Layout

```
memloader/                        # repo root = plugin root (contains ida-plugin.json)
├── ida-plugin.json               # Plugin Manager manifest
├── README.md                     # Shown on plugins.hex-rays.com
├── memloader_entry.py           # Entry point: PLUGIN_FIX plugin
└── memloader/                    # Python package
    ├── __init__.py
    ├── loaders/
    │   ├── zip_loader.py         # IDA loader: accept_file + load_file for ZIPs
    │   └── url_loader.py         # IDA loader: accept_file + load_file for URLs
    └── core.py                   # Shared loading pipeline
```

When installed by HCLI, this lands in `$IDAUSR/plugins/memloader/`. The plugin creates symlinks in `$IDAUSR/loaders/`:
- `$IDAUSR/loaders/memloader_zip_loader.py` → symlink to `memloader/loaders/zip_loader.py`
- `$IDAUSR/loaders/memloader_url_loader.py` → symlink to `memloader/loaders/url_loader.py`

## Component Details

### memloader_entry.py (PLUGIN_FIX)

```
class MemloaderPlugmod(ida_idaapi.plugmod_t):
    def __init__(self):
        - find IDA user loaders dir via os.path.join(ida_diskio.get_user_idadir(), "loaders")
        - create $IDAUSR/loaders/ if it doesn't exist
        - find own package dir via os.path.realpath(__file__)
        - remove any dangling memloader_*.py symlinks in loaders/
        - create symlinks to zip_loader.py and url_loader.py (skip if already valid)

    def run(self, arg):
        - no-op for POC

class MemloaderPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_HIDE | ida_idaapi.PLUGIN_MULTI
    wanted_name = "Memloader"

    def init(self):
        return MemloaderPlugmod()

def PLUGIN_ENTRY():
    return MemloaderPlugin()
```

Symlink creation strategy (cross-platform):
1. Try `os.symlink()` (works on Linux/macOS, Windows with dev mode)
2. Fall back to `os.link()` (hard link, same volume only)
3. If neither works, log a warning and don't install the loaders

### memloader/loaders/zip_loader.py (IDA Loader)

Top-level functions (IDA's Python loader protocol):

`accept_file(li, filename)`:
- Try to open `filename` with `zipfile.ZipFile`
- If it's a valid ZIP with at least one file, return the format name string
- Otherwise return 0

`load_file(li, neflags, format)`:
- Open the ZIP, list contents, prompt user via `ida_kernwin.ask_form()` dropdown
- Ask for password (default "infected") via `ida_kernwin.ask_str()`
- Extract selected file to `bytes` buffer
- Call into `memloader.core.load_buffer_into_ida(buffer, filename)`

### memloader/loaders/url_loader.py (IDA Loader)

`accept_file(li, filename)`:
- Return format name for any non-empty filename (same as original)

`load_file(li, neflags, format)`:
- Prompt for URL via `ida_kernwin.ask_str()`
- Download via `urllib.request.urlopen()` into `bytes` buffer
- Compute SHA256 via `hashlib.sha256()`, use as filename
- Call into `memloader.core.load_buffer_into_ida(buffer, sha256_name)`

### memloader/core.py (Shared Loading Pipeline)

`load_buffer_into_ida(buffer: bytes, filename: str)`:
1. Fix IDA environment (PATH_TYPE_CMD, PATH_TYPE_IDB, root filename)
2. Check for existing IDB, prompt to override
3. `li = ida_loader.create_bytearray_linput(buffer)`
4. `linfos = ida_loader.build_loaders_list(li, "")`
5. If linfos and recognized format: `ida_loader.load_nonbinary_file("", li, "", 0, linfos)` — IDA's built-in loaders handle all format-specific work (image base, compiler, architecture, signatures)
6. If no loader matched: prompt for shellcode mode, use `ida_bytes.mem2base()`
7. Trigger auto-analysis: `ida_auto.auto_wait()`
8. Save database

## Key Risks and Validation Steps

### 1. ~~Python binding availability~~ (RESOLVED)
`create_bytearray_linput()`, `build_loaders_list()`, and `load_nonbinary_file()` are confirmed available in `ida_loader` Python bindings.

### 2. Symlink timing
PLUGIN_FIX init() must complete before IDA scans the loaders directory for a file-open operation. User confirmed from IDA source that loaders are scanned per-file-open, not at IDA startup. This means the symlinks will be in place by the time they're needed.

### 3. Windows symlinks
`os.symlink()` requires SeCreateSymbolicLinkPrivilege (admin or developer mode). The fallback to `os.link()` (hard link) covers the common case. If neither works, the plugin logs a warning and the loaders aren't available.

### 4. Dangling symlinks on uninstall
If the plugin is removed via HCLI, the symlinks persist pointing at deleted files. On next IDA startup with the plugin gone, no cleanup runs. The stale symlinks remain until manually removed.

Mitigation options (for future, not POC):
- Document that a restart and manual cleanup is needed after uninstall
- Make the loader files gracefully handle import failures

### 5. ~~IDA user dir vs install dir~~ (RESOLVED)
Using `$IDAUSR/loaders/` — confirmed that IDA scans this location. Always writable, no admin needed.

## Headless / idalib Mode

The loaders use interactive prompts (`ask_form`, `ask_str`, `ask_yn`) that don't work in headless mode. Each loader must detect batch mode and adapt:

**ZIP loader in headless mode:**
- `IdaCommandOptions.file_member` may specify which ZIP member to extract (needs verification)
- Password: use default ("infected") without prompting
- If no member specified, extract the first file

**URL loader in headless mode:**
- Inherently interactive (prompts for URL) — not testable end-to-end in headless mode
- Core loading logic (`load_buffer_into_ida`) is testable independently

**Headless detection:** Check `ida_kernwin.cvar.batch` or equivalent.

## Testing

In-process idalib: tests import `idapro` directly and call `idapro.open_database()` / `idapro.close_database()` within the pytest process. No subprocess orchestration or JSON IPC — direct assertions on IDA state.

### Test layout

```
tests/
├── conftest.py                   # shared fixtures: IDAUSR setup, idalib lifecycle
├── test_symlinks.py              # pure Python: symlink creation, dangling cleanup
├── test_zip_loader.py            # in-process idalib: ZIP with PE → verify segments
├── test_shellcode.py             # in-process idalib: raw bytes → shellcode fallback
└── test_core.py                  # in-process idalib: load_buffer_into_ida() directly
```

### conftest.py

**session_idauser** (session-scoped fixture):
1. Create isolated `idauser/` with `plugins/` and `loaders/` subdirectories
2. Copy `.hexlic` license files from `~/.idapro/`
3. Run `hcli ida set-default <install_dir>` with `HCLI_IDAUSR` pointed at the test dir
4. Accept EULA via `ida_registry.reg_write_int("EULA 90", 1)`
5. Create symlinks from `idauser/loaders/` to our loader .py files (replaces the PLUGIN_FIX plugin's job during testing)
6. Set `IDAUSR` env var so idalib finds the test directory

**ida_db** (function-scoped fixture):
```python
@pytest.fixture
def ida_db(tmp_path, session_idauser, test_binary):
    binary = tmp_path / test_binary.name
    shutil.copy(test_binary, binary)
    os.environ["IDAUSR"] = str(session_idauser)
    idapro.open_database(str(binary), run_auto_analysis=True)
    yield tmp_path
    idapro.close_database()
```

### Pure Python tests (no IDA required)

**test_symlinks.py:**
- Create symlinks in a temp dir, verify they point to the right targets
- Create a dangling symlink, run cleanup, verify it's removed
- Verify working symlinks are left alone during cleanup

### idalib integration tests (in-process)

**test_zip_loader.py:**
```python
def test_zip_loads_pe(session_idauser, test_binary, tmp_path):
    zip_path = tmp_path / "test.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.write(test_binary, "test.exe")

    os.environ["IDAUSR"] = str(session_idauser)
    idapro.open_database(str(zip_path), run_auto_analysis=True)

    import ida_segment
    seg = ida_segment.get_first_seg()
    assert seg is not None

    idapro.close_database()
```

**test_core.py:**
- Opens any binary via `idapro.open_database()`, then calls `load_buffer_into_ida()` directly with a PE buffer
- Verifies the `create_bytearray_linput` → `build_loaders_list` → `load_nonbinary_file` pipeline produces segments

**test_shellcode.py:**
- Creates a ZIP with raw bytes, opens via our loader, verifies a single CODE segment with the expected bytes

### Open questions for test infrastructure

1. **Loader invocation via idapro.open_database()**: When called with a .zip path, does idalib scan `$IDAUSR/loaders/` and call our loader's `accept_file()`? Need to verify this works end-to-end.

2. **file_member in headless mode**: Need to confirm how to select a specific ZIP member without interactive prompts. `IdaCommandOptions.file_member` may work, or we fall back to extracting the first file in batch mode.

3. **IDA state between tests**: `idapro.close_database()` should reset state sufficiently for the next test. If not, we may need subprocess isolation for some tests.

### GitHub Actions CI

```yaml
name: tests
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions: read-all

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v9
        with: { python-version: "3.12" }
      - run: uv venv && uv pip install pytest
      - run: uv run pytest tests/test_symlinks.py -v

  idalib-tests:
    name: idalib tests on IDA ${{ matrix.ida-version }} / Python ${{ matrix.python-version }}
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.10", "3.14"]
        ida-version: ["9.2", "latest"]
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v9
        with:
          python-version: ${{ matrix.python-version }}
          enable-cache: true

      - name: Create test environment
        run: |
          uv venv
          uv pip install idapro ida-domain pytest

      - name: Install IDA
        run: |
          uv run --with ida-hcli hcli \
            ida install \
            --download-id "ida-pro:${{ matrix.ida-version }}" \
            --license-id "${IDA_LICENSE_ID}" \
            --install-dir="${{ runner.temp }}/app/ida" \
            --accept-eula --set-default --yes
        env:
          HCLI_API_KEY: ${{ secrets.HCLI_API_KEY }}
          IDA_LICENSE_ID: ${{ secrets.IDA_LICENSE_ID }}

      - name: Run tests
        run: uv run --no-project python -m pytest tests/ -v
        env:
          IDA_LICENSE_ID: ${{ secrets.IDA_LICENSE_ID }}
```

## Implementation Order

1. **memloader/core.py** — the shared loading pipeline using ida_loader APIs
2. **memloader/loaders/zip_loader.py** — ZIP loader with accept_file + load_file (with headless mode support)
3. **memloader/loaders/url_loader.py** — URL loader
4. **memloader_entry.py** — PLUGIN_FIX symlink manager
5. **tests/** — pure Python tests first, then idalib integration tests
6. **ida-plugin.json** — manifest for Plugin Manager
7. **.github/workflows/test.yml** — CI configuration

## Verification

1. `pytest tests/ -k "not test_idalib"` passes on any machine (no IDA required)
2. `pytest tests/test_idalib/` passes on a machine with IDA + idalib
3. Install the plugin package to `$IDAUSR/plugins/memloader/`
4. Restart IDA — confirm symlinks appear in `$IDAUSR/loaders/`
5. Open a password-protected ZIP containing a PE — confirm the loader appears in IDA's loader selection, file loads correctly
6. Open a file and choose the URL loader — confirm download, SHA256 naming, loading
7. Test shellcode fallback — open a ZIP containing raw bytes, confirm binary/shellcode mode
8. Test on Linux/macOS — confirm cross-platform behavior
