"""Shared fixtures for ida-codemode-sandbox tests.

Opens the shared test binary with real IDA Pro analysis.
No mocks — every test exercises real IDA.
"""

import shutil
from pathlib import Path

import pytest

from ida_codemode_api import create_api_from_database

TESTS_DIR = Path(__file__).resolve().parent
TEST_BINARY = TESTS_DIR / "data" / "Practical Malware Analysis Lab 01-01.exe_"


# ---------------------------------------------------------------------------
# Session-scoped fixtures — IDA analysis is expensive, shared across tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def test_binary(tmp_path_factory) -> Path:
    """Copy the shared test binary to a temp dir to avoid IDB conflicts."""
    work = tmp_path_factory.mktemp("ida_codemode_sandbox")
    dest = work / TEST_BINARY.name
    shutil.copy(TEST_BINARY, dest)
    return dest


@pytest.fixture(scope="session")
def db(test_binary):
    """Open the test binary with IDA Pro and yield the Database."""
    from ida_domain import Database
    from ida_domain.database import IdaCommandOptions

    options = IdaCommandOptions(auto_analysis=True, new_database=False)
    with Database.open(str(test_binary), options, save_on_close=False) as database:
        yield database


@pytest.fixture(scope="session")
def ida_fns(db):
    """The dict of IDA wrapper callables for direct-call testing."""
    return create_api_from_database(db)


@pytest.fixture(scope="session")
def first_func(ida_fns):
    """Address of the first function IDA found (for generic tests)."""
    result = ida_fns["get_functions"]()
    assert "error" not in result, result.get("error", "unknown error")
    functions = result["functions"]
    assert len(functions) > 0, "IDA found no functions in the test binary"
    return functions[0]
