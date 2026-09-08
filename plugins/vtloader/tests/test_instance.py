from pathlib import Path

import pytest
from vtloader.instance import (
    build_open_command,
    build_vt_load_command,
    create_vt_input_file,
    get_ida_executable,
)


def test_vt_input_file_is_minimal_and_named_after_hash(monkeypatch, tmp_path):
    temp_root = tmp_path / "temp"
    temp_root.mkdir()
    monkeypatch.setattr("vtloader.instance.tempfile.gettempdir", lambda: str(temp_root))

    sha256 = "5" + "a" * 63
    input_file = create_vt_input_file(sha256)

    assert input_file.name == sha256
    assert input_file.read_bytes() == b"\0" * 16
    assert input_file.parent.parent == temp_root


def test_vt_load_command_selects_loader_and_passes_hash_and_database(tmp_path):
    ida = tmp_path / "ida"
    sha256 = "ab" * 32
    database = tmp_path / "Downloads" / (sha256 + ".i64")
    input_file = tmp_path / sha256

    command = build_vt_load_command(ida, sha256, database, input_file)

    assert command[0] == str(ida)
    assert "-Tvtloader" in command
    assert f"-Ovtloader:sha256={sha256}" in command
    assert f"-o{database}" in command
    assert command[-1] == str(input_file)


def test_open_command_passes_database_only(tmp_path):
    assert build_open_command(Path("/opt/ida/ida"), tmp_path / "x.i64") == [
        "/opt/ida/ida",
        str(tmp_path / "x.i64"),
    ]


def test_ida_executable_must_exist(tmp_path):
    with pytest.raises(FileNotFoundError):
        get_ida_executable(tmp_path)
    exe = tmp_path / "ida"
    exe.write_bytes(b"")
    exe_name = get_ida_executable(tmp_path).name
    assert exe_name in ("ida", "ida.exe")
