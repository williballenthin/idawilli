import hashlib
import zipfile

from conftest import PMA_ARCHIVE, PMA_PASSWORD, URL_ARGS
from idahelpers import get_filetype, get_root_filename, get_segments
from pe import IMAGE_BASE, TEXT_RVA


def test_url_loader_downloads_and_loads_pe(
    open_database, tmp_path, tiny_pe, http_server
):
    (tmp_path / "sample.exe").write_bytes(tiny_pe)
    trigger = tmp_path / "anything.bin"
    trigger.write_bytes(b"ignored input file")

    with open_database(
        trigger, f"{URL_ARGS} -Omemloader:url={http_server}/sample.exe"
    ) as rc:
        assert rc == 0
        assert get_root_filename() == hashlib.sha256(tiny_pe).hexdigest()
        assert any(
            s.name == ".text" and s.start == IMAGE_BASE + TEXT_RVA
            for s in get_segments()
        )


def test_url_loader_fails_on_missing_resource(open_database, tmp_path, http_server):
    trigger = tmp_path / "anything.bin"
    trigger.write_bytes(b"ignored input file")
    with open_database(
        trigger, f"{URL_ARGS} -Omemloader:url={http_server}/missing.exe"
    ) as rc:
        assert rc != 0


def test_url_loader_stays_out_of_the_way_in_batch_mode(open_database, tmp_path):
    """Without a url option the URL loader must not claim files, so plain binaries still load."""
    import ida_ida

    raw = tmp_path / "raw.bin"
    raw.write_bytes(b"\x90" * 32)
    with open_database(raw) as rc:
        assert rc == 0
        assert ida_ida.inf_get_filetype() == ida_ida.f_BIN
        assert get_root_filename() == "raw.bin"


def test_url_loader_downloads_pma_sample(open_database, tmp_path, http_server):
    import ida_ida

    with zipfile.ZipFile(PMA_ARCHIVE) as zf:
        sample = zf.read("Lab01-01.exe", pwd=PMA_PASSWORD)
    (tmp_path / "Lab01-01.exe").write_bytes(sample)
    trigger = tmp_path / "anything.bin"
    trigger.write_bytes(b"ignored input file")

    with open_database(
        trigger, f"{URL_ARGS} -Omemloader:url={http_server}/Lab01-01.exe"
    ) as rc:
        assert rc == 0
        assert get_filetype() == ida_ida.f_PE
        assert get_root_filename() == hashlib.sha256(sample).hexdigest()
