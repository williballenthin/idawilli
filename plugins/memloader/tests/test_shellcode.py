import zipfile

from conftest import ZIP_ARGS
from idahelpers import get_bytes, get_filetype, get_root_filename, get_segments

SHELLCODE = b"\x90\x90\x31\xc0\xc3" + b"\xcc" * 11


def write_shellcode_zip(path):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("payload.bin", SHELLCODE)
    return path


def test_unrecognized_member_loads_as_32bit_shellcode(open_database, tmp_path):
    path = write_shellcode_zip(tmp_path / "sc.zip")
    with open_database(path, ZIP_ARGS) as rc:
        assert rc == 0
        (seg,) = get_segments()
        assert seg.name == "shellcode"
        assert (seg.start, seg.end) == (0, len(SHELLCODE))
        assert seg.bitness == 1
        assert get_bytes(0, len(SHELLCODE)) == SHELLCODE
        assert get_root_filename() == "payload.bin"


def test_shellcode_bitness_option(open_database, tmp_path):
    import ida_ida

    path = write_shellcode_zip(tmp_path / "sc.zip")
    with open_database(path, f"{ZIP_ARGS} -Omemloader:bitness=64") as rc:
        assert rc == 0
        (seg,) = get_segments()
        assert seg.bitness == 2
        assert ida_ida.inf_is_64bit()
        assert get_filetype() == ida_ida.f_LOADER
