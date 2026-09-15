from flirt_data_pack.sig import build_dummy_sig


def test_dummy_sig_has_flirt_magic():
    data = build_dummy_sig()
    assert data[:6] == b"IDASGN"


def test_dummy_sig_embeds_library_name():
    data = build_dummy_sig("mylib")
    assert b"mylib\x00" in data


def test_dummy_sig_default_name():
    data = build_dummy_sig()
    assert b"dummy\x00" in data
