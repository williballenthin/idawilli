import hashlib
import os
import zipfile

import pytest
from conftest import PMA_ARCHIVE, PMA_PASSWORD
from vtloader.virustotal import (
    InvalidHashError,
    VirusTotalClient,
    VirusTotalError,
    describe_api_error,
    normalize_sha256,
)

PMA_EXE_SHA256 = "58898bd42c5bd3bf9b1389f0eee5b39cd59180e8370eb9ea838a0b327bd6fe47"
needs_vt = pytest.mark.skipif(
    not os.environ.get("VT_API_KEY"), reason="VT_API_KEY not set"
)


def read_pma_exe() -> bytes:
    with zipfile.ZipFile(PMA_ARCHIVE) as zf:
        return zf.read("Lab01-01.exe", pwd=PMA_PASSWORD)


@pytest.fixture(scope="session")
def vt_client() -> VirusTotalClient:
    return VirusTotalClient(os.environ["VT_API_KEY"])


def test_normalize_accepts_uppercase_and_whitespace():
    assert normalize_sha256(f"  {PMA_EXE_SHA256.upper()}\n") == PMA_EXE_SHA256


@pytest.mark.parametrize(
    "text",
    ["", "abc", "g" * 64, PMA_EXE_SHA256[:63], "d41d8cd98f00b204e9800998ecf8427e"],
)
def test_normalize_rejects_non_sha256(text):
    with pytest.raises(InvalidHashError):
        normalize_sha256(text)


def test_describe_api_error_includes_server_message():
    body = b'{"error": {"code": "ForbiddenError", "message": "You are not allowed"}}'
    assert (
        describe_api_error(403, body)
        == "the API key is not allowed to download files (You are not allowed)"
    )
    assert describe_api_error(500, b"<html>") == "HTTP status 500"


def test_unreachable_server_is_reported():
    client = VirusTotalClient("irrelevant", "http://127.0.0.1:9/api/v3")
    with pytest.raises(VirusTotalError, match="cannot reach"):
        client.get_download_url(PMA_EXE_SHA256)


@needs_vt
def test_download_returns_the_pma_sample_bytes(vt_client):
    sample = read_pma_exe()
    assert hashlib.sha256(sample).hexdigest() == PMA_EXE_SHA256
    assert vt_client.download_file(PMA_EXE_SHA256) == sample


@needs_vt
def test_wrong_key_is_reported_as_invalid_key():
    with pytest.raises(VirusTotalError, match="API key is not valid"):
        VirusTotalClient("0" * 64).get_download_url(PMA_EXE_SHA256)


@needs_vt
def test_unknown_hash_is_reported_as_not_found(vt_client):
    with pytest.raises(VirusTotalError, match="no file with this hash"):
        vt_client.get_download_url(
            hashlib.sha256(b"vtloader: not a real file").hexdigest()
        )
