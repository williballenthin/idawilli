"""Evaluation task function.

Wraps the ida-codemode-agent to run a single non-interactive evaluation.
This is the function that pydantic-evals calls for each case in the dataset.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


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

    thinking_budget: int | None = None
    """Optional thinking token budget."""

    extra_model_settings: dict[str, Any] | None = None
    """Additional pydantic-ai ModelSettings."""

    system_prompt_override: str | None = None
    """Optional system prompt override."""


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
    from pydantic_ai import ModelSettings
    from pydantic_evals.dataset import increment_eval_metric, set_eval_attribute

    from ida_codemode_agent.cli import ScriptEvaluator, build_agent

    # Record model info as eval attributes
    set_eval_attribute("model_id", inputs.model_id)
    set_eval_attribute("model_label", inputs.model_label)
    if inputs.thinking_budget is not None:
        set_eval_attribute("thinking_budget", inputs.thinking_budget)

    # Build model settings
    settings_dict: dict[str, Any] = {}
    if inputs.extra_model_settings:
        settings_dict.update(inputs.extra_model_settings)
    if inputs.thinking_budget is not None:
        settings_dict["thinking"] = {"budget_tokens": inputs.thinking_budget}

    model_settings = ModelSettings(**settings_dict) if settings_dict else None

    # Build the agent (reuses the same code path as interactive CLI)
    evaluator = ScriptEvaluator(sandbox=inputs.sandbox)

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

    # Extract and record usage metrics
    usage = result.usage()
    total_tokens = (usage.total_tokens or 0) if usage else 0
    request_tokens = (usage.request_tokens or 0) if usage else 0
    response_tokens = (usage.response_tokens or 0) if usage else 0

    increment_eval_metric("total_tokens", total_tokens)
    increment_eval_metric("request_tokens", request_tokens)
    increment_eval_metric("response_tokens", response_tokens)

    # Count turns (response messages = LLM round-trips)
    all_messages = result.all_messages()
    turn_count = sum(1 for m in all_messages if getattr(m, "kind", None) == "response")
    increment_eval_metric("turns", turn_count)

    # Count tool calls
    tool_call_count = 0
    for msg in all_messages:
        parts = getattr(msg, "parts", [])
        for part in parts:
            if getattr(part, "part_kind", None) == "tool-call":
                tool_call_count += 1
    increment_eval_metric("tool_calls", tool_call_count)

    return output


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
