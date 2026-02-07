"""Shared fixtures for ida-sandbox tests.

Opens the repository's shared test binary with real IDA Pro analysis.
No mocks — every test exercises real IDA.
"""

import shutil
from pathlib import Path

import pytest

from ida_sandbox.sandbox import _build_ida_functions

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TEST_BINARY = REPO_ROOT / "tests" / "data" / "Practical Malware Analysis Lab 01-01.exe_"


# ---------------------------------------------------------------------------
# Session-scoped fixtures — IDA analysis is expensive, shared across tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def test_binary(tmp_path_factory) -> Path:
    """Copy the shared test binary to a temp dir to avoid IDB conflicts."""
    work = tmp_path_factory.mktemp("ida_sandbox")
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
    return _build_ida_functions(db)


@pytest.fixture(scope="session")
def first_func(ida_fns):
    """Address of the first function IDA found (for generic tests)."""
    functions = ida_fns["enumerate_functions"]()
    assert len(functions) > 0, "IDA found no functions in the test binary"
    return functions[0]
