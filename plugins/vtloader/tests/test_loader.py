"""The VirusTotal loader against the live API. Needs ``VT_API_KEY`` in the environment."""

import hashlib
import os
import zipfile

import pytest
from conftest import PMA_ARCHIVE, PMA_PASSWORD, VT_ARGS
from idahelpers import get_filetype, get_root_filename
from vtloader.instance import create_vt_input_file

PMA_EXE_SHA256 = "58898bd42c5bd3bf9b1389f0eee5b39cd59180e8370eb9ea838a0b327bd6fe47"
needs_vt = pytest.mark.skipif(
    not os.environ.get("VT_API_KEY"), reason="VT_API_KEY not set"
)


def test_sha256_prompt_accepts_a_hash_that_starts_with_a_number(ida, monkeypatch):
    import ida_kernwin
    from vtloader import loader
    from vtloader.options import LoadOptions

    sha256 = PMA_EXE_SHA256
    histories = []

    def fake_ask_str(default, history, text):
        histories.append(history)
        return sha256

    monkeypatch.setattr(loader, "is_batch_mode", lambda: False)
    monkeypatch.setattr(ida_kernwin, "ask_str", fake_ask_str)

    assert loader.choose_sha256(LoadOptions()) == sha256
    assert histories == [ida_kernwin.HIST_SRCH]


@pytest.fixture
def trigger(tmp_path):
    path = tmp_path / "anything.bin"
    path.write_bytes(b"ignored input file")
    return path


def test_generated_vt_input_file_reaches_loader(open_database, monkeypatch):
    import ida_ida
    from vtloader import loader

    sha256 = "5" + "a" * 63
    input_file = create_vt_input_file(sha256)
    with zipfile.ZipFile(PMA_ARCHIVE) as zf:
        sample = zf.read("Lab01-01.exe", pwd=PMA_PASSWORD)
    monkeypatch.setattr(loader, "fetch", lambda requested: sample)

    with open_database(input_file, f"{VT_ARGS} -Ovtloader:sha256={sha256}") as rc:
        assert rc == 0
        assert get_filetype() == ida_ida.f_PE
        assert get_root_filename() == sha256


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
        assert ida_ida.inf_get_filetype() == ida_ida.f_BIN
        assert get_root_filename() == "raw.bin"
