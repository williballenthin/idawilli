"""Shared fixtures for ida-codemode-eval tests."""

from __future__ import annotations

from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
PACKAGE_DIR = TESTS_DIR.parent
EVALS_DIR = PACKAGE_DIR / "evals"
