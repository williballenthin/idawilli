"""Evaluation task function.

Wraps the ida-codemode-agent to run a single non-interactive evaluation.
This is the function that pydantic-evals calls for each case in the dataset.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class EvalInputs:
    """Inputs for a single evaluation run.

    Passed as ``case.inputs`` to the task function.
    """

    prompt: str
    """The user prompt to send to the agent."""

    model_id: str
    """Model identifier (e.g. openrouter:anthropic/claude-sonnet-4-20250514)."""

    model_label: str
    """Human-readable model label for reports."""

    sandbox: Any
    """Pre-initialized IdaSandbox instance (shared across runs)."""

    reasoning_effort: str | None = None
    """OpenRouter reasoning effort level (xhigh, high, medium, low, minimal, none)."""

    extra_model_settings: dict[str, Any] | None = None
    """Additional pydantic-ai ModelSettings."""

    system_prompt_override: str | None = None
    """Optional system prompt override."""


def _extract_cost_from_messages(all_messages: list[Any]) -> float:
    """Extract total cost from ModelResponse.provider_details across all messages.

    OpenRouter returns ``usage.cost`` (real USD including cache discounts)
    in every chat completion response. PydanticAI's OpenRouterModel parses
    this into ``ModelResponse.provider_details['cost']``.

    Since an agentic run may involve multiple LLM requests (tool call loops),
    we sum the cost from every ModelResponse in the conversation.
    """
    total_cost = 0.0
    for msg in all_messages:
        if getattr(msg, "kind", None) != "response":
            continue
        provider_details = getattr(msg, "provider_details", None)
        if provider_details and isinstance(provider_details, dict):
            cost = provider_details.get("cost")
            if cost is not None:
                total_cost += float(cost)
    return total_cost


def _serialize_messages(messages: list[Any]) -> list[Any]:
    """Serialize pydantic-ai message history for JSON session logging."""
    serialized: list[Any] = []
    for msg in messages:
        if hasattr(msg, "model_dump"):
            try:
                serialized.append(msg.model_dump(mode="json"))
                continue
            except Exception:
                pass
        serialized.append(repr(msg))
    return serialized


async def run_eval_task(inputs: EvalInputs) -> str:
    """Execute a single evaluation run of the ida-codemode agent.

    This function:
    1. Builds the agent with the specified model
    2. Runs the agent non-interactively with the given prompt
    3. Records token usage, turn count, and cost as eval metrics
    4. Returns the agent's final text output

    The output is then assessed by evaluators (ContainsC2Indicator, etc.)
    to determine success and capture performance metrics.
    """
    from pydantic_evals.dataset import increment_eval_metric, set_eval_attribute

    from ida_codemode_agent.cli import ScriptEvaluator, SessionLogger, build_agent

    # Create a session logger for this eval run so traces can be reviewed later.
    session_logger = SessionLogger.create_for_eval(inputs.model_label)
    session_logger.log(
        "session_start",
        mode="eval",
        model_id=inputs.model_id,
        model_label=inputs.model_label,
        reasoning_effort=inputs.reasoning_effort,
        system_prompt_override=inputs.system_prompt_override is not None,
    )
    session_logger.log("user", content=inputs.prompt)

    try:
        # Record model info as eval attributes
        set_eval_attribute("model_id", inputs.model_id)
        set_eval_attribute("model_label", inputs.model_label)
        if inputs.reasoning_effort is not None:
            set_eval_attribute("reasoning_effort", inputs.reasoning_effort)

        # Build model settings using OpenRouterModelSettings when reasoning is configured
        model_settings = _build_model_settings(inputs)

        # Build the agent (reuses the same code path as interactive CLI)
        evaluator = ScriptEvaluator(
            sandbox=inputs.sandbox,
            on_evaluation=lambda script, result: session_logger.log(
                "tool_evaluation",
                script=script,
                result=result,
            ),
        )

        # If a custom system prompt is provided, we need to build the agent differently
        if inputs.system_prompt_override is not None:
            agent = _build_agent_with_prompt(inputs.model_id, evaluator, inputs.system_prompt_override)
        else:
            agent = build_agent(inputs.model_id, evaluator)

        # Run the agent non-interactively
        kwargs: dict[str, Any] = {}
        if model_settings is not None:
            kwargs["model_settings"] = model_settings

        result = await agent.run(inputs.prompt, **kwargs)
        output = str(result.output) if result.output else ""

        session_logger.log("assistant", content=output)

        # Extract and record usage metrics
        usage = result.usage()
        total_tokens = (usage.total_tokens or 0) if usage else 0
        input_tokens = (usage.input_tokens or 0) if usage else 0
        output_tokens = (usage.output_tokens or 0) if usage else 0

        increment_eval_metric("total_tokens", total_tokens)
        increment_eval_metric("input_tokens", input_tokens)
        increment_eval_metric("output_tokens", output_tokens)

        # Count turns and tool calls from the message history
        all_messages = result.all_messages()
        turn_count = sum(1 for m in all_messages if getattr(m, "kind", None) == "response")
        increment_eval_metric("turns", turn_count)

        tool_call_count = 0
        tool_call_fail_count = 0
        for msg in all_messages:
            parts = getattr(msg, "parts", [])
            for part in parts:
                part_kind = getattr(part, "part_kind", None)
                if part_kind == "tool-call":
                    tool_call_count += 1
                elif part_kind == "retry-prompt":
                    # PydanticAI emits a RetryPromptPart when a tool call fails
                    # (e.g. validation error, ModelRetry exception)
                    tool_call_fail_count += 1
        increment_eval_metric("tool_calls", tool_call_count)
        increment_eval_metric("tool_call_failures", tool_call_fail_count)

        # Extract real cost from OpenRouter's inline usage.cost field.
        # PydanticAI's OpenRouterModel parses this into
        # ModelResponse.provider_details['cost'] on every response.
        # This is the actual USD charged, including cache discounts.
        cost_usd = _extract_cost_from_messages(all_messages)
        if cost_usd > 0:
            increment_eval_metric("cost_usd", cost_usd)

        # Log the full message history so we can replay the entire conversation.
        session_logger.log("messages", history=_serialize_messages(all_messages))

        return output

    except Exception as exc:
        session_logger.log("error", message=f"{type(exc).__name__}: {exc}")
        raise

    finally:
        session_logger.log("session_end")
        session_logger.close()


def _build_model_settings(inputs: EvalInputs) -> Any:
    """Build the appropriate ModelSettings for the model provider.

    Uses OpenRouterModelSettings when the model is an OpenRouter model,
    configuring reasoning effort and/or extra settings as needed.
    Falls back to base ModelSettings for other providers.
    """
    has_reasoning = inputs.reasoning_effort is not None
    has_extra = bool(inputs.extra_model_settings)
    is_openrouter = inputs.model_id.startswith("openrouter:")

    if not has_reasoning and not has_extra:
        return None

    if is_openrouter:
        try:
            from pydantic_ai.models.openrouter import OpenRouterModelSettings

            settings_dict: dict[str, Any] = {}
            if inputs.extra_model_settings:
                settings_dict.update(inputs.extra_model_settings)

            if has_reasoning:
                settings_dict["openrouter_reasoning"] = {
                    "effort": inputs.reasoning_effort,
                }

            return OpenRouterModelSettings(**settings_dict)
        except ImportError:
            logger.warning(
                "pydantic_ai.models.openrouter.OpenRouterModelSettings not available, "
                "falling back to base ModelSettings"
            )

    # Fallback for non-OpenRouter models or when import fails
    from pydantic_ai import ModelSettings

    settings_dict = {}
    if inputs.extra_model_settings:
        settings_dict.update(inputs.extra_model_settings)

    return ModelSettings(**settings_dict) if settings_dict else None


def _build_agent_with_prompt(model: Any, evaluator: Any, system_prompt: str) -> Any:
    """Build an agent with a custom system prompt (for prompt A/B testing)."""
    from pydantic_ai import Agent

    agent = Agent(
        model,
        system_prompt=system_prompt,
        output_type=str,
        defer_model_check=True,
    )

    if hasattr(agent, "tool_plain"):

        @agent.tool_plain
        async def evaluate_ida_script(script: str) -> str:
            """Execute sandboxed Python source against the opened IDA database."""
            return evaluator.evaluate(script)
    else:
        from pydantic_ai import RunContext

        @agent.tool
        async def evaluate_ida_script(_ctx: RunContext[Any], script: str) -> str:
            """Execute sandboxed Python source against the opened IDA database."""
            return evaluator.evaluate(script)

    return agent
