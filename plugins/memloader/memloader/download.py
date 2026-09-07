"""Fetch a file from a URL into memory."""

import hashlib
import logging
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
TIMEOUT_SECONDS = 60


class DownloadError(Exception):
    pass


def download(url: str) -> bytes:
    """Download ``url`` and return its body.

    Raises:
        DownloadError: the URL is invalid, unreachable, or returns an error status.
    """
    if not url.strip():
        raise DownloadError("URL is empty")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return response.read()
    except (urllib.error.URLError, ValueError, OSError) as e:
        raise DownloadError(f"cannot download {url}: {e}") from e


def sha256_name(buffer: bytes) -> str:
    return hashlib.sha256(buffer).hexdigest()
