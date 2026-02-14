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
    PromptInputResult,
    SessionLogger,
    ScriptEvaluator,
    _available_models,
    _estimate_context_tokens,
    _format_compact_token_count,
    _parse_evaluate_tool_result_text,
    _render_tool_result,
    _validate_model_name,
    main,
    parse_args,
    resolve_database_plan,
    run_repl,
)


def test_default_model_resolution() -> None:
    args = parse_args(["/tmp/fake-input.i64"])
    assert args.model == DEFAULT_MODEL
    assert ":" in args.model


def test_parse_args_accepts_list_models_without_path() -> None:
    args = parse_args(["--list-models"])
    assert args.list_models is True
    assert args.idb_path is None


def test_parse_args_accepts_initial_prompt() -> None:
    args = parse_args(["/tmp/fake-input", "--prompt", "Summarize imports"])
    assert args.initial_prompt == "Summarize imports"

    alias_args = parse_args(["/tmp/fake-input", "--initial-prompt", "Summarize imports"])
    assert alias_args.initial_prompt == "Summarize imports"


def test_base_system_prompt_reinforces_expect_ok_guard_pattern() -> None:
    prompt = cli.BASE_SYSTEM_PROMPT
    assert "for every `x = expect_ok(...)`, guard with `if x is not None:`" in prompt
    assert "call `help(\"callback_name\")` first" in prompt
    assert "Prefer `decompile_function_at(...)` pseudocode over raw disassembly" in prompt


def test_base_system_prompt_mentions_minimal_retry_on_typing_errors() -> None:
    prompt = cli.BASE_SYSTEM_PROMPT
    assert "send a minimal follow-up script" in prompt


def test_available_models_contains_test_model() -> None:
    models = _available_models()
    assert "test" in models


def test_available_models_contains_default_model() -> None:
    models = _available_models()
    assert DEFAULT_MODEL in models


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
    rc = main(["/definitely/missing/file.i64", "--model", "x"])
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


class TestReplInputControls:
    def test_initial_prompt_runs_before_interactive_input(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        events = iter([PromptInputResult(kind="text", text="/quit")])

        monkeypatch.setattr(
            cli,
            "_prompt_user_with_context_estimate",
            lambda *_args, **_kwargs: next(events),
        )

        seen_inputs: list[str] = []

        def fake_run_agent_turn(
            *,
            agent,
            user_input: str,
            history,
            console,
            session_logger,
        ):
            seen_inputs.append(user_input)
            return [*history, user_input]

        monkeypatch.setattr(cli, "run_agent_turn", fake_run_agent_turn)

        console = Console(width=120, record=True)
        logger = SessionLogger(tmp_path / "session.jsonl")
        try:
            rc = run_repl(object(), console, logger, initial_prompt="summarize imports")
        finally:
            logger.close()

        assert rc == 0
        assert seen_inputs == ["summarize imports"]

    def test_clear_command_is_no_longer_special(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        events = iter(
            [
                PromptInputResult(kind="text", text="/clear"),
                PromptInputResult(kind="text", text="/quit"),
            ]
        )

        monkeypatch.setattr(
            cli,
            "_prompt_user_with_context_estimate",
            lambda *_args, **_kwargs: next(events),
        )

        seen_inputs: list[str] = []

        def fake_run_agent_turn(
            *,
            agent,
            user_input: str,
            history,
            console,
            session_logger,
        ):
            seen_inputs.append(user_input)
            return [*history, user_input]

        monkeypatch.setattr(cli, "run_agent_turn", fake_run_agent_turn)

        console = Console(width=120, record=True)
        logger = SessionLogger(tmp_path / "session.jsonl")
        try:
            rc = run_repl(object(), console, logger)
        finally:
            logger.close()

        assert rc == 0
        assert seen_inputs == ["/clear"]

    def test_ctrl_d_twice_exits_repl(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        events = iter(
            [
                PromptInputResult(kind="eof"),
                PromptInputResult(kind="eof"),
            ]
        )
        monkeypatch.setattr(
            cli,
            "_prompt_user_with_context_estimate",
            lambda *_args, **_kwargs: next(events),
        )
        monkeypatch.setattr(
            cli,
            "run_agent_turn",
            lambda **_kwargs: pytest.fail("run_agent_turn should not be called on double Ctrl-D exit"),
        )

        console = Console(width=120, record=True)
        logger = SessionLogger(tmp_path / "session.jsonl")
        try:
            rc = run_repl(object(), console, logger)
        finally:
            logger.close()

        assert rc == 0
        assert "Press Ctrl-D again to exit." in console.export_text()

    def test_ctrl_d_counter_resets_after_real_input(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        events = iter(
            [
                PromptInputResult(kind="eof"),
                PromptInputResult(kind="text", text="hello"),
                PromptInputResult(kind="text", text="/quit"),
            ]
        )
        monkeypatch.setattr(
            cli,
            "_prompt_user_with_context_estimate",
            lambda *_args, **_kwargs: next(events),
        )

        seen_inputs: list[str] = []

        def fake_run_agent_turn(
            *,
            agent,
            user_input: str,
            history,
            console,
            session_logger,
        ):
            seen_inputs.append(user_input)
            return [*history, user_input]

        monkeypatch.setattr(cli, "run_agent_turn", fake_run_agent_turn)

        console = Console(width=120, record=True)
        logger = SessionLogger(tmp_path / "session.jsonl")
        try:
            rc = run_repl(object(), console, logger)
        finally:
            logger.close()

        assert rc == 0
        assert seen_inputs == ["hello"]

    def test_keyboard_interrupt_at_prompt_propagates(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def raise_keyboard_interrupt(*_args, **_kwargs):
            raise KeyboardInterrupt

        monkeypatch.setattr(
            cli,
            "_prompt_user_with_context_estimate",
            raise_keyboard_interrupt,
        )

        console = Console(width=120, record=True)
        logger = SessionLogger(tmp_path / "session.jsonl")
        try:
            with pytest.raises(KeyboardInterrupt):
                run_repl(object(), console, logger)
        finally:
            logger.close()

    def test_keyboard_interrupt_during_agent_turn_propagates(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        events = iter([PromptInputResult(kind="text", text="analyze imports")])
        monkeypatch.setattr(
            cli,
            "_prompt_user_with_context_estimate",
            lambda *_args, **_kwargs: next(events),
        )

        def fake_run_agent_turn(**_kwargs):
            raise KeyboardInterrupt

        monkeypatch.setattr(cli, "run_agent_turn", fake_run_agent_turn)

        console = Console(width=120, record=True)
        logger = SessionLogger(tmp_path / "session.jsonl")
        try:
            with pytest.raises(KeyboardInterrupt):
                run_repl(object(), console, logger)
        finally:
            logger.close()


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
