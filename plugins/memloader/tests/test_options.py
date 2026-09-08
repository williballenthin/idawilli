import pytest
from memloader.options import LoadOptions, OptionsError


def test_empty_string_gives_defaults():
    opts = LoadOptions.from_plugin_options("")
    assert opts == LoadOptions()
    assert opts.sha256 is None
    assert opts.bitness == 32


def test_parses_all_keys():
    opts = LoadOptions.from_plugin_options(f"sha256={'ab' * 32};bitness=64")
    assert opts.sha256 == "ab" * 32
    assert opts.bitness == 64


def test_sha256_is_normalized():
    assert LoadOptions.from_plugin_options(f"sha256={'AB' * 32}").sha256 == "ab" * 32


@pytest.mark.parametrize(
    "text",
    [
        "sha256",
        "bogus=1",
        "bitness=16",
        "bitness=abc",
        "sha256=abc",
        "member=a.exe",
        "url=http://x/y",
    ],
)
def test_rejects_malformed_options(text):
    with pytest.raises(OptionsError):
        LoadOptions.from_plugin_options(text)
