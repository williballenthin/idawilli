"""Shared fixtures for ida-codemode-agent tests."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parents[1]
SAMPLE_BINARY = (
    REPO_ROOT
    / "ida-codemode-sandbox"
    / "tests"
    / "data"
    / "Practical Malware Analysis Lab 01-01.exe_"
)


@pytest.fixture(scope="session")
def sample_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Copy the shared sample binary to avoid IDB collisions across tests."""
    assert SAMPLE_BINARY.exists(), f"missing sample binary: {SAMPLE_BINARY}"

    work = tmp_path_factory.mktemp("ida_codemode_agent")
    dest = work / SAMPLE_BINARY.name
    shutil.copy(SAMPLE_BINARY, dest)
    return dest


@pytest.fixture(scope="session")
def db(sample_binary: Path):
    """Open the sample binary with IDA and yield the Database handle."""
    from ida_domain import Database
    from ida_domain.database import IdaCommandOptions

    options = IdaCommandOptions(auto_analysis=True, new_database=False)
    with Database.open(str(sample_binary), options, save_on_close=False) as database:
        yield database
