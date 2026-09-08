import io
import zipfile

import pytest
from idahelpers import get_root_filename, get_segments
from pe import IMAGE_BASE, TEXT_RVA


@pytest.fixture
def blank_database(open_database, tmp_path):
    raw = tmp_path / "blank.bin"
    raw.write_bytes(b"\x00" * 16)
    with open_database(raw) as rc:
        assert rc == 0
        yield tmp_path


def test_load_buffer_runs_native_pe_loader(blank_database, tiny_pe):
    import ida_ida
    import ida_loader
    from memloader.core import load_buffer_into_ida
    from memloader.options import LoadOptions

    result = load_buffer_into_ida(
        tiny_pe,
        "direct.exe",
        ida_loader.NEF_FIRST | ida_loader.NEF_SEGS,
        LoadOptions(),
        blank_database,
    )

    assert not result.is_shellcode
    assert result.loader is not None
    assert "PE" in result.loader.format_name
    assert result.filetype == ida_ida.f_PE
    assert any(
        s.name == ".text" and s.start == IMAGE_BASE + TEXT_RVA for s in get_segments()
    )
    assert get_root_filename() == "direct.exe"


def test_load_buffer_rejects_empty_and_archives(blank_database, tiny_pe):
    import ida_loader
    from memloader.core import LoadError, load_buffer_into_ida
    from memloader.options import LoadOptions

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


def test_kernel_lists_loaders_for_pe(blank_database, tiny_pe):
    from memloader.kernel import IdaKernel

    kernel = IdaKernel.from_idadir()
    with (
        kernel.bytearray_linput(tiny_pe) as li,
        kernel.loaders_list(li, "x.exe") as loaders,
    ):
        assert loaders.entries
        assert "PE" in loaders.best.format_name
        assert loaders.best.processor == "metapc"
        assert not loaders.best.is_archive

    with (
        kernel.bytearray_linput(b"\x00" * 64) as li,
        kernel.loaders_list(li, "x.bin") as loaders,
    ):
        assert loaders.entries == []
