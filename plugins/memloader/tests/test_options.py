import pytest
from memloader.options import DEFAULT_PASSWORD, LoadOptions, OptionsError


def test_empty_string_gives_defaults():
    opts = LoadOptions.from_plugin_options("")
    assert opts == LoadOptions()
    assert opts.password == DEFAULT_PASSWORD
    assert opts.member is None
    assert opts.bitness == 32


def test_parses_all_keys():
    opts = LoadOptions.from_plugin_options(
        "member=a/b.exe;password=secret;url=http://x/y;bitness=64"
    )
    assert opts.member == "a/b.exe"
    assert opts.password == "secret"
    assert opts.url == "http://x/y"
    assert opts.bitness == 64


def test_value_may_contain_equals_sign():
    opts = LoadOptions.from_plugin_options("url=http://x/y?a=b")
    assert opts.url == "http://x/y?a=b"


def test_sha256_is_normalized():
    digest = "AB" * 32
    assert LoadOptions.from_plugin_options(f"sha256={digest}").sha256 == "ab" * 32


@pytest.mark.parametrize("text", ["member", "bogus=1", "bitness=16", "sha256=abc"])
def test_rejects_malformed_options(text):
    with pytest.raises(OptionsError):
        LoadOptions.from_plugin_options(text)
