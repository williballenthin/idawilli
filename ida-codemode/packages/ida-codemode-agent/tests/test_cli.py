"""High-value tests for ida-codemode-agent CLI and sandbox integration behavior."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from rich.console import Console

from ida_codemode_agent.cli import (
    THINKING_LEVELS,
    ScriptEvaluator,
    _build_openai_compatible_model,
    _build_thinking_model_settings,
    _parse_openai_compatible_url,
    _render_tool_result,
    _validate_model_name,
    main,
    parse_args,
    resolve_database_plan,
)


def test_main_validates_model_before_database_resolution(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["/definitely/missing/file.i64", "--model", "x"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "invalid model" in err


def test_removed_provider_flag_is_rejected() -> None:
    with pytest.raises(SystemExit):
        parse_args(["/tmp/fake-input.i64", "--provider", "openrouter"])


def test_removed_script_size_flag_is_rejected() -> None:
    with pytest.raises(SystemExit):
        parse_args(["/tmp/fake-input.i64", "--max-script-chars", "1000"])


def test_removed_idb_control_flags_are_rejected() -> None:
    for flag in ("--new-database", "--auto-analysis", "--no-auto-analysis", "--save-on-close"):
        with pytest.raises(SystemExit):
            parse_args(["/tmp/fake-input.i64", flag])


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
    def test_existing_database_is_accepted(self, tmp_path: Path) -> None:
        database = tmp_path / "sample.i64"
        database.write_bytes(b"IDA")

        plan = resolve_database_plan(database)

        assert plan.open_path == database

    def test_non_database_path_is_rejected(self, tmp_path: Path) -> None:
        binary = tmp_path / "sample.exe"
        binary.write_bytes(b"MZ")

        with pytest.raises(FileNotFoundError):
            resolve_database_plan(binary)

    def test_missing_database_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            resolve_database_plan(tmp_path / "missing.i64")


class TestParseOpenAICompatibleUrl:
    def test_http_url_with_model(self) -> None:
        result = _parse_openai_compatible_url("http://localhost:1234/v1:my-model")
        assert result == ("http://localhost:1234/v1", "my-model")

    def test_https_url_with_model(self) -> None:
        result = _parse_openai_compatible_url("https://api.example.com/v1:gpt-4o")
        assert result == ("https://api.example.com/v1", "gpt-4o")

    def test_url_with_slash_in_model_name(self) -> None:
        result = _parse_openai_compatible_url(
            "http://localhost:1234/v1:lmstudio-community/Meta-Llama-3.1-8B"
        )
        assert result == (
            "http://localhost:1234/v1",
            "lmstudio-community/Meta-Llama-3.1-8B",
        )

    def test_url_without_model_name_returns_none(self) -> None:
        result = _parse_openai_compatible_url("http://localhost:1234/v1")
        assert result is None

    def test_url_without_path(self) -> None:
        result = _parse_openai_compatible_url("http://localhost:1234:my-model")
        assert result == ("http://localhost:1234", "my-model")

    def test_non_url_returns_none(self) -> None:
        assert _parse_openai_compatible_url("openrouter:google/gemini") is None
        assert _parse_openai_compatible_url("anthropic:claude-sonnet-4-20250514") is None

    def test_https_no_port_with_model(self) -> None:
        result = _parse_openai_compatible_url("https://my-server.com/v1:llama3")
        assert result == ("https://my-server.com/v1", "llama3")


class TestValidateModelNameUrl:
    def test_valid_url_model_accepted(self) -> None:
        _validate_model_name("http://localhost:1234/v1:my-model")

    def test_url_without_model_name_rejected(self) -> None:
        with pytest.raises(ValueError, match="missing a model name suffix"):
            _validate_model_name("http://localhost:1234/v1")

    def test_url_model_main_validates_before_database(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["/definitely/missing/file.i64", "--model", "http://localhost:1234/v1"])
        assert rc == 2
        err = capsys.readouterr().err
        assert "missing a model name suffix" in err


class TestBuildOpenAICompatibleModel:
    def test_creates_model_object(self) -> None:
        from pydantic_ai.models.openai import OpenAIChatModel

        model = _build_openai_compatible_model("http://localhost:1234/v1", "test-model")
        assert isinstance(model, OpenAIChatModel)


class TestThinkingArgParsing:
    def test_default_is_none(self) -> None:
        args = parse_args(["/tmp/fake.i64"])
        assert args.thinking is None

    def test_bare_flag_gives_medium(self) -> None:
        args = parse_args(["/tmp/fake.i64", "--thinking"])
        assert args.thinking == "medium"

    def test_explicit_level(self) -> None:
        for level in THINKING_LEVELS:
            args = parse_args(["/tmp/fake.i64", "--thinking", level])
            assert args.thinking == level

    def test_invalid_level_rejected(self) -> None:
        with pytest.raises(SystemExit):
            parse_args(["/tmp/fake.i64", "--thinking", "turbo"])


class TestBuildThinkingModelSettings:
    def test_openrouter_returns_reasoning_effort(self) -> None:
        settings = _build_thinking_model_settings("openrouter:google/gemini-3-flash", "high")
        assert settings is not None
        assert settings["openrouter_reasoning"] == {"effort": "high"}

    def test_anthropic_returns_adaptive_thinking(self) -> None:
        settings = _build_thinking_model_settings("anthropic:claude-sonnet-4-20250514", "high")
        assert settings is not None
        assert settings["anthropic_thinking"] == {"type": "adaptive"}
        assert settings["anthropic_effort"] == "high"

    def test_anthropic_maps_xhigh_to_max(self) -> None:
        settings = _build_thinking_model_settings("anthropic:claude-sonnet-4-20250514", "xhigh")
        assert settings is not None
        assert settings["anthropic_effort"] == "max"

    def test_openai_returns_reasoning_effort(self) -> None:
        settings = _build_thinking_model_settings("openai:gpt-4o", "medium")
        assert settings is not None
        assert settings["openai_reasoning_effort"] == "medium"

    def test_url_model_returns_reasoning_effort(self) -> None:
        settings = _build_thinking_model_settings("http://localhost:1234/v1:my-model", "low")
        assert settings is not None
        assert settings["openai_reasoning_effort"] == "low"

    def test_unknown_provider_returns_none(self) -> None:
        settings = _build_thinking_model_settings("mystery:some-model", "high")
        assert settings is None


class TestSampleAnalysisIntegration:
    def test_script_evaluator_can_read_database_metadata(self, db) -> None:
        from ida_codemode_sandbox import IdaSandbox

        sandbox = IdaSandbox(db)
        evaluator = ScriptEvaluator(sandbox)

        result = evaluator.evaluate(
            """
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
