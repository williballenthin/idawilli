"""IDA loader: fetch a file from VirusTotal by SHA-256 and load it without writing it to disk.

The loader offers itself for every input file. When selected, it ignores the input
file and asks for the hash instead. The database is named after the hash and written
to the user's Downloads directory.
"""

import logging

import ida_kernwin

from memloader.core import (
    UserCancelled,
    get_options,
    is_batch_mode,
    load_buffer_into_ida,
    wait_box,
)
from memloader.options import LoadOptions
from memloader.settings import (
    VT_FORMAT_NAME,
    VT_HASH_PROMPT,
    get_vt_api_key,
    get_vt_database_dir,
)
from memloader.virustotal import VirusTotalClient, normalize_sha256

logger = logging.getLogger(__name__)


def accept_file(li, filename):
    if is_batch_mode() and get_options().sha256 is None:
        return 0
    return VT_FORMAT_NAME


def choose_sha256(options: LoadOptions) -> str:
    """The hash from the options, or from a prompt in interactive mode.

    Raises:
        UserCancelled: no hash was given.
        InvalidHashError: the entered text is not a SHA-256 digest.
    """
    if options.sha256 is not None:
        return options.sha256
    if is_batch_mode():
        raise UserCancelled("no hash given; pass -Omemloader:sha256=... in batch mode")
    text = ida_kernwin.ask_str("", ida_kernwin.HIST_SRCH, VT_HASH_PROMPT)
    if not text:
        raise UserCancelled("no hash entered")
    return normalize_sha256(text)


def fetch(sha256: str) -> bytes:
    """Download the file from VirusTotal with the key from the plugin settings.

    Raises:
        ApiKeyMissingError: no key is configured.
        SettingsError: the settings cannot be read.
        VirusTotalError: VirusTotal refused the request or the download failed.
    """
    client = VirusTotalClient(get_vt_api_key())
    with wait_box(f"Downloading {sha256[:16]}... from VirusTotal"):
        return client.download_file(sha256)


def load_file(li, neflags, format):
    options = get_options()
    sha256 = choose_sha256(options)
    buffer = fetch(sha256)
    logger.info("downloaded %d bytes for %s from VirusTotal", len(buffer), sha256)
    load_buffer_into_ida(
        buffer, sha256, neflags, options, database_dir=get_vt_database_dir()
    )
    return 1
