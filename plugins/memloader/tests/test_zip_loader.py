import shutil
import zipfile

from conftest import PMA_ARCHIVE, ZIP_ARGS
from idahelpers import get_bytes, get_filetype, get_root_filename, get_segments
from pe import CODE, IMAGE_BASE, TEXT_RVA, TEXT_SIZE
from zipcrypto import make_encrypted_zip


def write_zip(path, files: dict[str, bytes]):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return path


def assert_pe_loaded():
    import ida_ida

    assert get_filetype() == ida_ida.f_PE
    text = [s for s in get_segments() if s.name == ".text"]
    assert len(text) == 1
    assert text[0].start == IMAGE_BASE + TEXT_RVA
    assert text[0].end >= IMAGE_BASE + TEXT_RVA + TEXT_SIZE
    assert get_bytes(text[0].start, len(CODE)) == CODE


def test_zip_with_pe_loads_member_via_pe_loader(open_database, tmp_path, tiny_pe):
    path = write_zip(tmp_path / "sample.zip", {"sample.exe": tiny_pe})
    with open_database(path, ZIP_ARGS) as rc:
        assert rc == 0
        assert_pe_loaded()
        assert get_root_filename() == "sample.exe"


def test_zip_member_selected_by_option(open_database, tmp_path, tiny_pe):
    path = write_zip(
        tmp_path / "many.zip", {"readme.txt": b"hello", "bin/sample.exe": tiny_pe}
    )
    with open_database(path, f"{ZIP_ARGS} -Omemloader:member=sample.exe") as rc:
        assert rc == 0
        assert_pe_loaded()
        assert get_root_filename() == "sample.exe"


def test_zip_batch_mode_defaults_to_first_member(open_database, tmp_path, tiny_pe):
    path = write_zip(
        tmp_path / "many.zip", {"first.exe": tiny_pe, "second.txt": b"hello"}
    )
    with open_database(path, ZIP_ARGS) as rc:
        assert rc == 0
        assert get_root_filename() == "first.exe"


def test_encrypted_zip_uses_default_password(open_database, tmp_path, tiny_pe):
    path = tmp_path / "enc.zip"
    path.write_bytes(make_encrypted_zip({"sample.exe": tiny_pe}, "infected"))
    with open_database(path, ZIP_ARGS) as rc:
        assert rc == 0
        assert_pe_loaded()


def test_encrypted_zip_with_custom_password(open_database, tmp_path, tiny_pe):
    path = tmp_path / "enc.zip"
    path.write_bytes(make_encrypted_zip({"sample.exe": tiny_pe}, "s3cret"))
    with open_database(path, f"{ZIP_ARGS} -Omemloader:password=s3cret") as rc:
        assert rc == 0
        assert_pe_loaded()


def test_encrypted_zip_with_wrong_password_fails_to_load(
    open_database, tmp_path, tiny_pe
):
    path = tmp_path / "enc.zip"
    path.write_bytes(make_encrypted_zip({"sample.exe": tiny_pe}, "s3cret"))
    with open_database(path, ZIP_ARGS) as rc:
        assert rc != 0


def test_nested_zip_is_rejected(open_database, tmp_path, tiny_pe):
    inner = tmp_path / "inner.zip"
    write_zip(inner, {"sample.exe": tiny_pe})
    path = write_zip(tmp_path / "outer.zip", {"inner.zip": inner.read_bytes()})
    with open_database(path, ZIP_ARGS) as rc:
        assert rc != 0


def test_database_is_saved_next_to_archive(open_database, tmp_path, tiny_pe):
    path = write_zip(tmp_path / "sample.zip", {"sample.exe": tiny_pe})
    with open_database(path, ZIP_ARGS, save=True) as rc:
        assert rc == 0
    produced = sorted(
        p.name for p in tmp_path.iterdir() if p.suffix in (".i64", ".idb")
    )
    assert produced, "no database written"


def test_pma_archive_loads_exe_by_default_and_dll_by_option(open_database, tmp_path):
    """The checked-in archive holds two real PE files, encrypted with the default password."""
    import ida_ida

    path = tmp_path / PMA_ARCHIVE.name
    shutil.copy(PMA_ARCHIVE, path)

    with open_database(path, ZIP_ARGS) as rc:
        assert rc == 0
        assert get_filetype() == ida_ida.f_PE
        assert get_root_filename() == "Lab01-01.exe"
        assert not ida_ida.inf_is_dll()

    with open_database(path, f"{ZIP_ARGS} -Omemloader:member=Lab01-01.dll") as rc:
        assert rc == 0
        assert get_filetype() == ida_ida.f_PE
        assert get_root_filename() == "Lab01-01.dll"
        assert ida_ida.inf_is_dll()
