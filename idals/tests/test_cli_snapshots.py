from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import idals
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "idals.py"
SNAPSHOT_DIR = PROJECT_ROOT / "tests" / "snapshots"
SAMPLE_BINARY_ARG = "../tests/data/Practical Malware Analysis Lab 01-01.exe_"


@dataclass(frozen=True)
class CliResult:
    returncode: int
    stdout: str
    stderr: str


def run_cli(args: list[str]) -> CliResult:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    return CliResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def read_snapshot(name: str) -> str:
    return (SNAPSHOT_DIR / name).read_text()


@pytest.fixture(scope="session", autouse=True)
def warm_cache() -> None:
    result = run_cli([SAMPLE_BINARY_ARG, "--no-color"])
    assert result.returncode == 0


def test_help_snapshot() -> None:
    result = run_cli([])
    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout == read_snapshot("help.stdout")


def test_version_snapshot() -> None:
    result = run_cli(["-v"])
    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout == read_snapshot("version.stdout")


def test_overview_snapshot() -> None:
    result = run_cli([SAMPLE_BINARY_ARG, "--no-color"])
    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout == read_snapshot("overview.stdout")


def test_disassembly_start_snapshot() -> None:
    result = run_cli([SAMPLE_BINARY_ARG, "0x401820", "--no-color"])
    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout == read_snapshot("disasm_start.stdout")


def test_disassembly_import_snapshot() -> None:
    result = run_cli([SAMPLE_BINARY_ARG, "CreateFileA", "--no-color"])
    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout == read_snapshot("disasm_import.stdout")


def test_disassembly_start_rva_snapshot() -> None:
    result = run_cli([SAMPLE_BINARY_ARG, "0x401820", "--offsets", "rva", "--no-color"])
    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout == read_snapshot("disasm_start_rva.stdout")


def test_disassembly_context_snapshot() -> None:
    result = run_cli([SAMPLE_BINARY_ARG, "0x40184C", "-A", "4", "-B", "4", "--no-color"])
    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout == read_snapshot("disasm_context.stdout")


def test_unmapped_error_snapshot() -> None:
    result = run_cli([SAMPLE_BINARY_ARG, "0xDEAD", "--no-color"])
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == read_snapshot("error_unmapped.stderr")


def test_symbol_error_snapshot() -> None:
    result = run_cli([SAMPLE_BINARY_ARG, "CreateFlie", "--no-color"])
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == read_snapshot("error_symbol.stderr")


def test_conflict_error_snapshot() -> None:
    result = run_cli([SAMPLE_BINARY_ARG, "--decompile", "--no-decompile"])
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == read_snapshot("error_conflict.stderr")


def test_offset_formatter_va_mode() -> None:
    formatter = idals.OffsetFormatter(
        mode="va",
        image_base=0x400000,
        bad_address=0xFFFFFFFF,
        file_offset_resolver=lambda ea: ea - 0x400000,
    )
    assert formatter.format_address(0x401820) == "0x401820"


def test_offset_formatter_rva_mode() -> None:
    formatter = idals.OffsetFormatter(
        mode="rva",
        image_base=0x400000,
        bad_address=0xFFFFFFFF,
        file_offset_resolver=lambda ea: ea - 0x400000,
    )
    assert formatter.format_address(0x401820) == "0x1820"


def test_offset_formatter_file_mode_handles_unmapped() -> None:
    formatter = idals.OffsetFormatter(
        mode="file",
        image_base=0x400000,
        bad_address=0xFFFFFFFF,
        file_offset_resolver=lambda ea: -1 if ea == 0xDEAD else 0x123,
    )
    assert formatter.format_address(0x401820) == "0x123"
    assert formatter.format_address(0xDEAD) == "N/A"
