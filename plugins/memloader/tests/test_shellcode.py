"""The shellcode fallback, for a download no IDA loader recognizes."""

from conftest import VT_ARGS
from idahelpers import get_bytes, get_filetype, get_root_filename, get_segments

SHELLCODE = b"\x90\x90\x31\xc0\xc3" + b"\xcc" * 11
SHA256 = "5" + "a" * 63


def fetch_shellcode(open_database, monkeypatch, tmp_path, args=""):
    """Open a database through the VT loader, with the download replaced by shellcode."""
    from memloader import vt_loader

    monkeypatch.setattr(vt_loader, "fetch", lambda requested: SHELLCODE)
    trigger = tmp_path / "anything.bin"
    trigger.write_bytes(b"ignored input file")
    return open_database(trigger, f"{VT_ARGS} -Omemloader:sha256={SHA256}{args}")


def test_unrecognized_download_loads_as_32bit_shellcode(
    open_database, monkeypatch, tmp_path
):
    with fetch_shellcode(open_database, monkeypatch, tmp_path) as rc:
        assert rc == 0
        (seg,) = get_segments()
        assert seg.name == "shellcode"
        assert (seg.start, seg.end) == (0, len(SHELLCODE))
        assert seg.bitness == 1
        assert get_bytes(0, len(SHELLCODE)) == SHELLCODE
        assert get_root_filename() == SHA256


def test_shellcode_bitness_option(open_database, monkeypatch, tmp_path):
    import ida_ida

    with fetch_shellcode(open_database, monkeypatch, tmp_path, ";bitness=64") as rc:
        assert rc == 0
        (seg,) = get_segments()
        assert seg.bitness == 2
        assert ida_ida.inf_is_64bit()
        assert get_filetype() == ida_ida.f_LOADER
