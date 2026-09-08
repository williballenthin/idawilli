"""Headless options passed to the loader via IDA's ``-O`` command line switch."""

import logging
from dataclasses import dataclass

from vtloader.virustotal import InvalidHashError, normalize_sha256

logger = logging.getLogger(__name__)

PLUGIN_OPTIONS_NAME = "vtloader"
DEFAULT_SHELLCODE_BITNESS = 32
KEYS = ("sha256", "bitness")


class OptionsError(ValueError):
    pass


@dataclass(frozen=True)
class LoadOptions:
    """Options that replace the interactive prompts when IDA runs in batch mode.

    Passed as ``-Ovtloader:key=value;key=value`` on the IDA command line.
    Entries are separated by ``;`` so that values may contain ``:``.
    """

    sha256: str | None = None
    bitness: int = DEFAULT_SHELLCODE_BITNESS

    @classmethod
    def from_plugin_options(cls, text: str) -> "LoadOptions":
        """Parse the string that IDA returns from ``get_plugin_options("vtloader")``.

        Raises:
            OptionsError: an entry is not ``key=value``, the key is unknown, bitness is
                not 32 or 64, or sha256 is not a hex digest.
        """
        values: dict[str, str] = {}
        for entry in filter(None, text.split(";")):
            key, sep, value = entry.partition("=")
            if not sep:
                raise OptionsError(f"expected key=value, got {entry!r}")
            if key not in KEYS:
                raise OptionsError(f"unknown option: {key}")
            values[key] = value

        bitness = values.get("bitness", str(DEFAULT_SHELLCODE_BITNESS))
        if bitness not in ("32", "64"):
            raise OptionsError(f"bitness must be 32 or 64, got {bitness!r}")

        try:
            sha256 = normalize_sha256(values["sha256"]) if "sha256" in values else None
        except InvalidHashError as e:
            raise OptionsError(str(e)) from e

        return cls(sha256=sha256, bitness=int(bitness))
