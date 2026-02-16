"""Tests for custom evaluators."""

from __future__ import annotations

from unittest.mock import MagicMock

from ida_codemode_eval.evaluators import (
    ContainsC2Indicator,
    TokenUsage,
    TurnCount,
)


def _make_context(
    output: str,
    metadata: dict | None = None,
    metrics: dict | None = None,
) -> MagicMock:
    ctx = MagicMock()
    ctx.output = output
    ctx.metadata = metadata or {}
    ctx.metrics = metrics or {}
    return ctx


def test_contains_c2_indicator_found() -> None:
    ev = ContainsC2Indicator()
    ctx = _make_context(
        output="The C2 server is at evil.example.com on port 443",
        metadata={"magic_string": "evil.example.com"},
    )
    assert ev.evaluate(ctx) is True


def test_contains_c2_indicator_not_found() -> None:
    ev = ContainsC2Indicator()
    ctx = _make_context(
        output="I could not find any C2 indicators.",
        metadata={"magic_string": "evil.example.com"},
    )
    assert ev.evaluate(ctx) is False


def test_contains_c2_indicator_case_insensitive() -> None:
    ev = ContainsC2Indicator(case_sensitive=False)
    ctx = _make_context(
        output="Found EVIL.EXAMPLE.COM in the binary",
        metadata={"magic_string": "evil.example.com"},
    )
    assert ev.evaluate(ctx) is True


def test_contains_c2_indicator_case_sensitive() -> None:
    ev = ContainsC2Indicator(case_sensitive=True)
    ctx = _make_context(
        output="Found EVIL.EXAMPLE.COM in the binary",
        metadata={"magic_string": "evil.example.com"},
    )
    assert ev.evaluate(ctx) is False


def test_token_usage_returns_metric() -> None:
    ev = TokenUsage()
    ctx = _make_context(output="", metrics={"total_tokens": 1500})
    assert ev.evaluate(ctx) == 1500.0


def test_token_usage_returns_zero_when_missing() -> None:
    ev = TokenUsage()
    ctx = _make_context(output="", metrics={})
    assert ev.evaluate(ctx) == 0.0


def test_turn_count_returns_metric() -> None:
    ev = TurnCount()
    ctx = _make_context(output="", metrics={"turns": 7})
    assert ev.evaluate(ctx) == 7.0
