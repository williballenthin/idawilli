"""Tests for ida-codemode-agent CLI helpers and integration behavior."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import pytest
from rich.console import Console

import ida_codemode_agent.cli as cli
from ida_codemode_agent.cli import (
    DEFAULT_MODEL,
    DEFAULT_PROVIDER,
    SessionLogger,
    ScriptEvaluator,
    _available_models,
    _estimate_context_tokens,
    _format_compact_token_count,
    _parse_evaluate_tool_result_text,
    _render_tool_result,
    _resolve_model_name,
    _validate_model_name,
    main,
    parse_args,
    resolve_database_plan,
)


def test_default_model_and_provider_resolution() -> None:
    args = parse_args(["/tmp/fake-input"])
    assert args.model == DEFAULT_MODEL
    assert args.provider == DEFAULT_PROVIDER
    assert _resolve_model_name(args.model, args.provider) == "openrouter:google/gemini-3-flash-preview"


def test_parse_args_accepts_list_models_without_path() -> None:
    args = parse_args(["--list-models"])
    assert args.list_models is True
    assert args.idb_path is None


def test_available_models_contains_test_model() -> None:
    models = _available_models()
    assert "test" in models


def test_available_models_contains_openrouter_default_model() -> None:
    models = _available_models()
    assert _resolve_model_name(DEFAULT_MODEL, DEFAULT_PROVIDER) in models


def test_validate_model_name_rejects_unknown_provider() -> None:
    with pytest.raises(Exception):
        _validate_model_name("not-a-provider:some-model")


def test_validate_model_name_rejects_unknown_openrouter_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-token")
    monkeypatch.setattr(cli, "_openrouter_model_ids", lambda: ("openrouter:google/gemini-3-flash-preview",))

    with pytest.raises(ValueError):
        _validate_model_name("openrouter:google/not-a-real-model")


def test_main_list_models_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["--list-models"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Available models" in out


def test_main_validates_model_before_database_resolution(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["/definitely/missing/file.i64", "--provider", "not-a-provider", "--model", "x"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "invalid model" in err


def test_parse_evaluate_tool_result_ok_blocks() -> None:
    parsed = _parse_evaluate_tool_result_text(
        "\n".join(
            [
                "status: ok",
                "stdout:",
                "Function: _main",
                "Address: 0x401440",
                "result:",
                "{'arch': 'metapc'}",
            ]
        )
    )

    assert parsed["status"] == "ok"
    assert "Function: _main" in parsed["stdout"]
    assert "Address: 0x401440" in parsed["stdout"]
    assert parsed["result"] == "{'arch': 'metapc'}"


def test_parse_evaluate_tool_result_error_blocks() -> None:
    parsed = _parse_evaluate_tool_result_text(
        "\n".join(
            [
                "status: error",
                "kind: runtime",
                "message: division by zero",
                "stderr-before-error:",
                "warning: demo",
                "error-detail:",
                "Traceback...",
            ]
        )
    )

    assert parsed["status"] == "error"
    assert parsed["kind"] == "runtime"
    assert parsed["message"] == "division by zero"
    assert parsed["stderr-before-error"] == "warning: demo"
    assert "Traceback" in parsed["error-detail"]


def test_parse_evaluate_tool_result_keeps_message_like_lines_inside_stdout() -> None:
    parsed = _parse_evaluate_tool_result_text(
        "\n".join(
            [
                "status: ok",
                "stdout:",
                "message: this belongs to stdout",
                "kind: this also belongs to stdout",
            ]
        )
    )

    assert parsed["status"] == "ok"
    assert "message: this belongs to stdout" in parsed["stdout"]
    assert "kind: this also belongs to stdout" in parsed["stdout"]


def test_format_compact_token_count() -> None:
    assert _format_compact_token_count(987) == "987"
    assert _format_compact_token_count(1_000) == "1k"
    assert _format_compact_token_count(12_345) == "12.3k"
    assert _format_compact_token_count(1_000_000) == "1M"


def test_estimate_context_tokens_grows_with_history() -> None:
    class DummyAgent:
        _system_prompts = ("system prompt",)

    base = _estimate_context_tokens(DummyAgent(), [])
    larger = _estimate_context_tokens(DummyAgent(), ["hello world", "another message"])

    assert base > 0
    assert larger > base


def test_configure_logging_suppresses_httpx_info() -> None:
    logging.getLogger("httpx").setLevel(logging.INFO)
    logging.getLogger("httpcore").setLevel(logging.INFO)

    cli._configure_logging()

    assert logging.getLogger("httpx").level == logging.WARNING
    assert logging.getLogger("httpcore").level == logging.WARNING


def test_render_evaluate_error_omits_duplicate_stderr_traceback() -> None:
    console = Console(width=120, record=True)
    tool_result = "\n".join(
        [
            "status: error",
            "kind: runtime",
            "message: boom",
            "stderr-before-error:",
            "Traceback (most recent call last):",
            "  File \"<string>\", line 1, in <module>",
            "ZeroDivisionError: division by zero",
            "error-detail:",
            "Traceback (most recent call last):",
            "  File \"<string>\", line 1, in <module>",
            "ZeroDivisionError: division by zero",
        ]
    )

    _render_tool_result(console, "evaluate_ida_script", tool_result)
    rendered = console.export_text()

    assert rendered.count("Traceback (most recent call last):") == 1


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
