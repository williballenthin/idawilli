"""IDA loader: download a file from a URL and load it without writing it to disk.

The loader offers itself for every input file. When selected, it ignores the input
file and asks for a URL instead. The database is named after the SHA256 of the
downloaded bytes.
"""

import logging

import ida_kernwin

from memloader.core import (
    UserCancelled,
    get_options,
    is_batch_mode,
    load_buffer_into_ida,
)
from memloader.download import download, sha256_name
from memloader.options import LoadOptions

logger = logging.getLogger(__name__)

FORMAT_NAME = "Memloader URL"


def accept_file(li, filename):
    if is_batch_mode() and get_options().url is None:
        return 0
    return FORMAT_NAME


def choose_url(options: LoadOptions) -> str:
    if options.url is not None:
        return options.url
    if is_batch_mode():
        raise UserCancelled("no URL given; pass -Omemloader:url=... in batch mode")
    url = ida_kernwin.ask_str("", ida_kernwin.HIST_FILE, "URL to download")
    if not url:
        raise UserCancelled("no URL entered")
    return url


def load_file(li, neflags, format):
    options = get_options()
    url = choose_url(options)
    buffer = download(url)
    name = sha256_name(buffer)
    logger.info("downloaded %d bytes from %s, sha256 %s", len(buffer), url, name)
    load_buffer_into_ida(buffer, name, neflags, options)
    return 1
