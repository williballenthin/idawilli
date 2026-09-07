"""Headless options passed to the loaders via IDA's ``-O`` command line switch."""

import logging
from dataclasses import dataclass

from memloader.virustotal import InvalidHashError, normalize_sha256

logger = logging.getLogger(__name__)

PLUGIN_OPTIONS_NAME = "memloader"
DEFAULT_PASSWORD = "infected"
DEFAULT_SHELLCODE_BITNESS = 32


class OptionsError(ValueError):
    pass


@dataclass(frozen=True)
class LoadOptions:
    """Options that replace the interactive prompts when IDA runs in batch mode.

    Passed as ``-Omemloader:key=value;key=value`` on the IDA command line.
    Entries are separated by ``;`` so that values may contain ``:`` (for example URLs).
    """

    member: str | None = None
    password: str = DEFAULT_PASSWORD
    url: str | None = None
    sha256: str | None = None
    bitness: int = DEFAULT_SHELLCODE_BITNESS

    @classmethod
    def from_plugin_options(cls, text: str) -> "LoadOptions":
        """Parse the string that IDA returns from ``get_plugin_options("memloader")``.

        Raises:
            OptionsError: an entry is not ``key=value``, the key is unknown, bitness is not
                32 or 64, or sha256 is not a hex digest.
        """
        values: dict[str, str] = {}
        for entry in filter(None, text.split(";")):
            key, sep, value = entry.partition("=")
            if not sep:
                raise OptionsError(f"expected key=value, got {entry!r}")
            values[key] = value

        unknown = set(values) - {"member", "password", "url", "sha256", "bitness"}
        if unknown:
            raise OptionsError(f"unknown option(s): {', '.join(sorted(unknown))}")

        bitness = DEFAULT_SHELLCODE_BITNESS
        if "bitness" in values:
            if values["bitness"] not in ("32", "64"):
                raise OptionsError(
                    f"bitness must be 32 or 64, got {values['bitness']!r}"
                )
            bitness = int(values["bitness"])

        sha256 = None
        if "sha256" in values:
            try:
                sha256 = normalize_sha256(values["sha256"])
            except InvalidHashError as e:
                raise OptionsError(str(e)) from e

        return cls(
            member=values.get("member"),
            password=values.get("password", DEFAULT_PASSWORD),
            url=values.get("url"),
            sha256=sha256,
            bitness=bitness,
        )
