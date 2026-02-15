"""Custom evaluators for ida-codemode evaluation.

These evaluators assess agent performance on reverse engineering tasks,
complementing the built-in pydantic-evals evaluators (MaxDuration, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic_evals.evaluators import Evaluator, EvaluatorContext


@dataclass
class ContainsC2Indicator(Evaluator[Any, str, Any]):
    """Pass if the agent output contains the expected C2 indicator string.

    The magic string is read from ``ctx.metadata["magic_string"]``.
    This is the primary success criterion for C2 extraction tasks.
    """

    case_sensitive: bool = False

    def evaluate(self, ctx: EvaluatorContext[Any, str, Any]) -> bool:
        metadata = ctx.metadata
        if not isinstance(metadata, dict):
            return False

        magic = metadata.get("magic_string", "")
        if not magic:
            return False

        output = ctx.output or ""
        if not self.case_sensitive:
            magic = magic.lower()
            output = output.lower()
        return magic in output


@dataclass
class TokenUsage(Evaluator[Any, str, Any]):
    """Report total token count as a numeric score.

    The task function must call ``increment_eval_metric("total_tokens", n)``
    for this evaluator to return a meaningful value.
    """

    def evaluate(self, ctx: EvaluatorContext[Any, str, Any]) -> float:
        return float(ctx.metrics.get("total_tokens", 0))


@dataclass
class RequestTokens(Evaluator[Any, str, Any]):
    """Report request (input) token count as a numeric score."""

    def evaluate(self, ctx: EvaluatorContext[Any, str, Any]) -> float:
        return float(ctx.metrics.get("request_tokens", 0))


@dataclass
class ResponseTokens(Evaluator[Any, str, Any]):
    """Report response (output) token count as a numeric score."""

    def evaluate(self, ctx: EvaluatorContext[Any, str, Any]) -> float:
        return float(ctx.metrics.get("response_tokens", 0))


@dataclass
class TurnCount(Evaluator[Any, str, Any]):
    """Report the number of agent turns (LLM request/response rounds).

    The task function must call ``increment_eval_metric("turns", n)``
    for this evaluator to return a meaningful value.
    """

    def evaluate(self, ctx: EvaluatorContext[Any, str, Any]) -> float:
        return float(ctx.metrics.get("turns", 0))


@dataclass
class EstimatedCost(Evaluator[Any, str, Any]):
    """Report estimated cost in USD as a numeric score.

    The task function must call ``increment_eval_metric("cost_usd", n)``
    for this evaluator to return a meaningful value.
    """

    def evaluate(self, ctx: EvaluatorContext[Any, str, Any]) -> float:
        return float(ctx.metrics.get("cost_usd", 0.0))


@dataclass
class ToolCallCount(Evaluator[Any, str, Any]):
    """Report the number of tool calls the agent made.

    The task function must call ``increment_eval_metric("tool_calls", n)``
    for this evaluator to return a meaningful value.
    """

    def evaluate(self, ctx: EvaluatorContext[Any, str, Any]) -> float:
        return float(ctx.metrics.get("tool_calls", 0))
