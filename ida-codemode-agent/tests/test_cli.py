"""Tests for ida-codemode-agent CLI helpers and integration behavior."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from ida_codemode_agent.cli import (
    DEFAULT_MODEL,
    DEFAULT_PROVIDER,
    SessionLogger,
    ScriptEvaluator,
    _resolve_model_name,
    parse_args,
    resolve_database_plan,
)


def test_default_model_and_provider_resolution() -> None:
    args = parse_args(["/tmp/fake-input"])
    assert args.model == DEFAULT_MODEL
    assert args.provider == DEFAULT_PROVIDER
    assert _resolve_model_name(args.model, args.provider) == "openrouter:google/gemini-3-flash-preview"


class TestDatabasePlanResolution:
    def test_binary_without_companion_database_creates_i64_plan(self, tmp_path: Path) -> None:
        binary = tmp_path / "sample.exe"
        binary.write_bytes(b"MZ")

        plan = resolve_database_plan(binary)

        assert plan.open_path == binary
        assert plan.creates_database is True
        assert plan.output_database == str(tmp_path / "sample.exe.i64")

    def test_binary_with_existing_companion_database_prefers_database(self, tmp_path: Path) -> None:
        binary = tmp_path / "sample.exe"
        database = tmp_path / "sample.exe.i64"
        binary.write_bytes(b"MZ")
        database.write_bytes(b"IDA")

        plan = resolve_database_plan(binary)

        assert plan.open_path == database
        assert plan.creates_database is False
        assert plan.output_database is None

    def test_missing_database_path_uses_matching_binary_for_creation(self, tmp_path: Path) -> None:
        binary = tmp_path / "sample.exe"
        requested_database = tmp_path / "sample.exe.i64"
        binary.write_bytes(b"MZ")

        plan = resolve_database_plan(requested_database)

        assert plan.open_path == binary
        assert plan.creates_database is True
        assert plan.output_database == str(requested_database)

    def test_missing_database_and_missing_binary_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            resolve_database_plan(tmp_path / "missing.exe.i64")


class TestSessionLogger:
    def test_writes_jsonl_records(self, tmp_path: Path) -> None:
        log_path = tmp_path / "session.jsonl"
        logger = SessionLogger(log_path)
        logger.log("user", content="hello")
        logger.log("assistant", content="world")
        logger.close()

        lines = log_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2

        first = json.loads(lines[0])
        second = json.loads(lines[1])

        assert first["event"] == "user"
        assert first["content"] == "hello"
        assert second["event"] == "assistant"
        assert second["content"] == "world"


class TestSampleAnalysisIntegration:
    def test_script_evaluator_can_read_database_metadata(self, db) -> None:
        from ida_codemode_sandbox import IdaSandbox

        sandbox = IdaSandbox(db)
        evaluator = ScriptEvaluator(sandbox)

        result = evaluator.evaluate(
            """
def expect_ok(payload):
    if "error" in payload:
        print("API error")
        return None
    return payload

meta = expect_ok(get_database_metadata())
if meta is not None:
    print("arch=" + meta["architecture"])
"""
        )

        assert "status: ok" in result
        assert "arch=metapc" in result

    def test_script_evaluator_can_count_functions(self, db) -> None:
        from ida_codemode_sandbox import IdaSandbox

        sandbox = IdaSandbox(db)
        evaluator = ScriptEvaluator(sandbox)

        result = evaluator.evaluate(
            """
def expect_ok(payload):
    if "error" in payload:
        print("API error")
        return None
    return payload

functions = expect_ok(get_functions())
if functions is not None:
    print("function_count=" + str(len(functions["functions"])))
"""
        )

        assert "status: ok" in result

        match = re.search(r"function_count=(\d+)", result)
        assert match is not None
        assert int(match.group(1)) > 0

    def test_script_evaluator_reports_runtime_error(self, db) -> None:
        from ida_codemode_sandbox import IdaSandbox

        sandbox = IdaSandbox(db)
        evaluator = ScriptEvaluator(sandbox)

        result = evaluator.evaluate("1 / 0")

        assert "status: error" in result
        assert "ZeroDivisionError" in result
