"""The shellcode fallback, for a download no IDA loader recognizes."""

from conftest import VT_ARGS
from idahelpers import get_bytes, get_filetype, get_root_filename, get_segments
from vtloader.instance import create_vt_input_file

SHELLCODE = b"\x90\x90\x31\xc0\xc3" + b"\xcc" * 11
SHA256 = "5" + "a" * 63


def fetch_shellcode(open_database, monkeypatch, args=""):
    """Open a database through the VT loader, with the download replaced by shellcode.

    Uses the same generated input file the plugin creates for a real load: IDA reads a
    block of it while initializing, and its 16 null bytes stay out of the way.
    """
    from vtloader import loader

    monkeypatch.setattr(loader, "fetch", lambda requested: SHELLCODE)
    input_file = create_vt_input_file(SHA256)
    return open_database(input_file, f"{VT_ARGS} -Ovtloader:sha256={SHA256}{args}")


def test_unrecognized_download_loads_as_32bit_shellcode(open_database, monkeypatch):
    with fetch_shellcode(open_database, monkeypatch) as rc:
        assert rc == 0
        (seg,) = get_segments()
        assert seg.name == "shellcode"
        assert (seg.start, seg.end) == (0, len(SHELLCODE))
        assert seg.bitness == 1
        assert get_bytes(0, len(SHELLCODE)) == SHELLCODE
        assert get_root_filename() == SHA256


def test_shellcode_bitness_option(open_database, monkeypatch):
    import ida_ida

    with fetch_shellcode(open_database, monkeypatch, ";bitness=64") as rc:
        assert rc == 0
        (seg,) = get_segments()
        assert seg.bitness == 2
        assert ida_ida.inf_is_64bit()
        assert get_filetype() == ida_ida.f_LOADER


def test_own_loader_declines_the_buffer_it_downloaded(ida, monkeypatch):
    """Otherwise vtloader is its own best candidate for an unrecognized download."""
    from vtloader import core, loader
    from vtloader.settings import VT_FORMAT_NAME

    monkeypatch.setattr(loader, "is_batch_mode", lambda: False)
    assert loader.accept_file(None, "x.bin") == VT_FORMAT_NAME

    monkeypatch.setattr(core, "_loading_buffer", True)
    assert loader.accept_file(None, "x.bin") == 0
