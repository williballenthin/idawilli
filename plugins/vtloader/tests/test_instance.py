import shutil

from vtloader.instance import create_vt_input_file


def test_vt_input_file_is_minimal_and_named_after_hash():
    """IDA reads a block of the input while initializing, even though the loader ignores it."""
    sha256 = "5" + "a" * 63
    first = create_vt_input_file(sha256)
    second = create_vt_input_file(sha256)
    try:
        assert first.name == sha256
        assert first.read_bytes() == b"\0" * 16
        # a private directory per launch, so a repeated load cannot reuse an older file
        assert first != second
    finally:
        shutil.rmtree(first.parent)
        shutil.rmtree(second.parent)
