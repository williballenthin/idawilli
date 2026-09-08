"""The VirusTotal loader through IDA. The live tests need ``VT_API_KEY`` in the environment."""

import hashlib
import os

import pytest
from conftest import VT_ARGS
from idahelpers import get_filetype, get_root_filename

PMA_EXE_SHA256 = "58898bd42c5bd3bf9b1389f0eee5b39cd59180e8370eb9ea838a0b327bd6fe47"
needs_vt = pytest.mark.skipif(
    not os.environ.get("VT_API_KEY"), reason="VT_API_KEY not set"
)


@pytest.fixture
def trigger(tmp_path):
    """An input file for the loader to ignore."""
    path = tmp_path / "anything.bin"
    path.write_bytes(b"ignored input file")
    return path


@needs_vt
def test_loader_fetches_and_loads_pma_sample(open_database, trigger, plugin_settings):
    import ida_ida

    plugin_settings({"vt_api_key": os.environ["VT_API_KEY"]})
    with open_database(
        trigger, f"{VT_ARGS} -Ovtloader:sha256={PMA_EXE_SHA256.upper()}"
    ) as rc:
        assert rc == 0
        assert get_filetype() == ida_ida.f_PE
        assert get_root_filename() == PMA_EXE_SHA256


@needs_vt
def test_loader_fails_for_unknown_hash(open_database, trigger, plugin_settings):
    plugin_settings({"vt_api_key": os.environ["VT_API_KEY"]})
    unknown = hashlib.sha256(b"vtloader: not a real file").hexdigest()
    with open_database(trigger, f"{VT_ARGS} -Ovtloader:sha256={unknown}") as rc:
        assert rc != 0


def test_loader_fails_without_api_key(open_database, trigger, plugin_settings):
    plugin_settings({})
    with open_database(trigger, f"{VT_ARGS} -Ovtloader:sha256={PMA_EXE_SHA256}") as rc:
        assert rc != 0


def test_loader_stays_out_of_the_way_in_batch_mode(open_database, tmp_path):
    """Without a sha256 option the loader must not claim files, so plain binaries still load."""
    import ida_ida

    raw = tmp_path / "raw.bin"
    raw.write_bytes(b"\x90" * 32)
    with open_database(raw) as rc:
        assert rc == 0
        assert get_filetype() == ida_ida.f_BIN
        assert get_root_filename() == "raw.bin"
