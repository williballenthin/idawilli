import pytest
from vtloader.options import LoadOptions, OptionsError


def test_parses_and_normalizes_all_keys():
    opts = LoadOptions.from_plugin_options(f"sha256={'AB' * 32};bitness=64")
    assert opts.sha256 == "ab" * 32
    assert opts.bitness == 64


def test_empty_string_gives_the_defaults():
    assert LoadOptions.from_plugin_options("") == LoadOptions()


@pytest.mark.parametrize(
    "text", ["sha256", "bogus=1", "bitness=16", "bitness=abc", "sha256=abc"]
)
def test_rejects_malformed_options(text):
    with pytest.raises(OptionsError):
        LoadOptions.from_plugin_options(text)
