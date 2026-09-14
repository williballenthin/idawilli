"""Fetch a file from VirusTotal into memory."""

import hashlib
import json
import logging
import re
import urllib.error
import urllib.request
from dataclasses import dataclass

logger = logging.getLogger(__name__)

API_URL = "https://www.virustotal.com/api/v3"
TIMEOUT_SECONDS = 120
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class VirusTotalError(Exception):
    pass


class InvalidHashError(VirusTotalError):
    pass


def normalize_sha256(text: str) -> str:
    """Return the lowercase hex digest in ``text``.

    Raises:
        InvalidHashError: ``text`` is not 64 hexadecimal characters.
    """
    digest = text.strip().lower()
    if not SHA256_PATTERN.match(digest):
        raise InvalidHashError(f"not a SHA-256 hex digest: {text.strip()!r}")
    return digest


def describe_api_error(status: int, body: bytes) -> str:
    """Turn a VirusTotal error response into a message for the user."""
    detail = ""
    try:
        error = json.loads(body).get("error", {})
        detail = error.get("message") or error.get("code") or ""
    except (ValueError, AttributeError):
        pass
    reasons = {
        401: "the API key is not valid",
        403: "the API key is not allowed to download files",
        404: "no file with this hash is known to VirusTotal",
        429: "the API quota is exhausted",
    }
    reason = reasons.get(status, f"HTTP status {status}")
    return f"{reason} ({detail})" if detail else reason


@dataclass(frozen=True)
class VirusTotalClient:
    api_key: str

    def get_download_url(self, sha256: str) -> str:
        """Ask VirusTotal for a short-lived URL that serves the file with ``sha256``.

        Raises:
            VirusTotalError: the key is rejected, the file is unknown, the quota is
                exhausted, or VirusTotal cannot be reached.
        """
        request = urllib.request.Request(
            f"{API_URL}/files/{sha256}/download_url",
            headers={"x-apikey": self.api_key, "accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                payload = json.loads(response.read())
        except urllib.error.HTTPError as e:
            raise VirusTotalError(
                f"VirusTotal refused {sha256}: {describe_api_error(e.code, e.read())}"
            ) from e
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise VirusTotalError(f"cannot reach VirusTotal: {e}") from e
        url = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(url, str) or not url:
            raise VirusTotalError("VirusTotal returned no download URL")
        return url

    def download_file(self, sha256: str) -> bytes:
        """Download the file with ``sha256`` and verify the bytes against the hash.

        Raises:
            VirusTotalError: see ``get_download_url``, or the download fails, or the
                bytes do not hash to ``sha256``.
        """
        url = self.get_download_url(sha256)
        logger.debug("downloading %s from %s", sha256, url)
        try:
            with urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS) as response:
                buffer = response.read()
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise VirusTotalError(
                f"cannot download {sha256} from VirusTotal: {e}"
            ) from e
        actual = hashlib.sha256(buffer).hexdigest()
        if actual != sha256:
            raise VirusTotalError(
                f"downloaded bytes hash to {actual}, expected {sha256}"
            )
        return buffer
