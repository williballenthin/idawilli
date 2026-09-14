"""The loading pipeline, driven directly from a database that idalib has opened."""

import io
import zipfile

import pytest
from idahelpers import get_bytes, get_filetype, get_root_filename, get_segments
from pe import IMAGE_BASE, TEXT_RVA

SHELLCODE = b"\x90\x90\x31\xc0\xc3" + b"\xcc" * 11
SHA256 = "5" + "a" * 63


@pytest.fixture
def blank_database(open_database, tmp_path):
    raw = tmp_path / "blank.bin"
    raw.write_bytes(b"\x00" * 16)
    with open_database(raw) as rc:
        assert rc == 0
        yield tmp_path


@pytest.fixture
def hash_option_database(open_database, tmp_path, tiny_pe):
    """A database opened from a PE while a ``sha256`` option is set.

    With a hash to fetch, the loader accepts any input, so it is a candidate for the
    buffers these tests hand to the pipeline; for the input file itself IDA's own PE
    loader outranks it. The PE occupies 0x401000, leaving address 0 free.
    """
    path = tmp_path / "input.exe"
    path.write_bytes(tiny_pe)
    with open_database(path, f"-Ovtloader:sha256={SHA256}") as rc:
        assert rc == 0
        yield tmp_path


def test_load_buffer_runs_the_native_pe_loader(blank_database, tiny_pe):
    import ida_ida
    import ida_loader
    from vtloader.core import load_buffer_into_ida
    from vtloader.options import LoadOptions

    load_buffer_into_ida(
        tiny_pe,
        "direct.exe",
        ida_loader.NEF_FIRST | ida_loader.NEF_SEGS,
        LoadOptions(),
        blank_database,
    )

    assert get_filetype() == ida_ida.f_PE
    assert any(
        s.name == ".text" and s.start == IMAGE_BASE + TEXT_RVA for s in get_segments()
    )
    assert get_root_filename() == "direct.exe"


def test_load_buffer_rejects_empty_and_archives(blank_database, tiny_pe):
    import ida_loader
    from vtloader.core import LoadError, load_buffer_into_ida
    from vtloader.options import LoadOptions

    with pytest.raises(LoadError):
        load_buffer_into_ida(
            b"", "empty", ida_loader.NEF_FIRST, LoadOptions(), blank_database
        )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("sample.exe", tiny_pe)
    with pytest.raises(LoadError, match="archive"):
        load_buffer_into_ida(
            buf.getvalue(),
            "inner.zip",
            ida_loader.NEF_FIRST,
            LoadOptions(),
            blank_database,
        )


def test_unrecognized_buffer_loads_as_shellcode(hash_option_database):
    """No IDA loader recognizes the buffer, and vtloader must not claim it either.

    A loader that accepts any input is otherwise its own best candidate for the
    download, and the load recurses instead of falling back to shellcode.
    """
    import ida_loader
    from vtloader.core import load_buffer_into_ida
    from vtloader.options import LoadOptions

    load_buffer_into_ida(
        SHELLCODE,
        SHA256,
        ida_loader.NEF_FIRST,
        LoadOptions(sha256=SHA256),
        hash_option_database,
    )

    (seg,) = [s for s in get_segments() if s.name == "shellcode"]
    assert (seg.start, seg.end) == (0, len(SHELLCODE))
    assert seg.bitness == 1
    assert get_bytes(0, len(SHELLCODE)) == SHELLCODE
    assert get_root_filename() == SHA256


def test_shellcode_bitness_option(hash_option_database):
    import ida_ida
    import ida_loader
    from vtloader.core import load_buffer_into_ida
    from vtloader.options import LoadOptions

    load_buffer_into_ida(
        SHELLCODE,
        SHA256,
        ida_loader.NEF_FIRST,
        LoadOptions(sha256=SHA256, bitness=64),
        hash_option_database,
    )

    (seg,) = [s for s in get_segments() if s.name == "shellcode"]
    assert seg.bitness == 2
    assert ida_ida.inf_is_64bit()
