"""Evaluation task function.

Wraps the ida-codemode-agent to run a single non-interactive evaluation.
This is the function that pydantic-evals calls for each case in the dataset.
"""

from __future__ import annotations

import logging
import os
import time
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


def _fetch_generation_cost(generation_id: str) -> float | None:
    """Query OpenRouter's generation stats API for the actual cost.

    OpenRouter returns ``total_cost`` in USD for each generation.
    See: https://openrouter.ai/docs/api/api-reference/generations/get-generation

    Returns the cost in USD, or None if the lookup fails.
    """
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        return None

    try:
        import httpx
    except ImportError:
        return None

    # OpenRouter may need a brief delay to finalize generation stats
    # for streaming responses. For non-streaming this is typically instant.
    max_retries = 3
    for attempt in range(max_retries):
        try:
            resp = httpx.get(
                f"https://openrouter.ai/api/v1/generation?id={generation_id}",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=10.0,
            )
            if resp.status_code == 404 and attempt < max_retries - 1:
                # Stats may not be ready yet
                time.sleep(1.0 * (attempt + 1))
                continue
            resp.raise_for_status()
            data = resp.json().get("data", {})
            total_cost = data.get("total_cost")
            if total_cost is not None:
                return float(total_cost)
            return None
        except Exception as exc:
            logger.debug("Failed to fetch generation cost (attempt %d): %s", attempt + 1, exc)
            if attempt < max_retries - 1:
                time.sleep(1.0 * (attempt + 1))
    return None


def _extract_generation_id(result: Any) -> str | None:
    """Extract the OpenRouter generation ID from the agent result.

    PydanticAI stores the raw response data in the message history.
    OpenRouter returns the generation ID as the ``id`` field in the
    chat completion response.
    """
    all_messages = result.all_messages()
    for msg in reversed(all_messages):
        # Look for model response messages which may carry the response ID
        if getattr(msg, "kind", None) == "response":
            parts = getattr(msg, "parts", [])
            for part in parts:
                # The model_response_id is sometimes surfaced on parts
                resp_id = getattr(part, "model_response_id", None)
                if resp_id and isinstance(resp_id, str):
                    return resp_id

    # Fallback: check if result itself has the ID
    # pydantic-ai may store it differently across versions
    if hasattr(result, "_result_response"):
        resp = result._result_response
        if hasattr(resp, "id") and isinstance(resp.id, str):
            return resp.id

    return None


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

    from ida_codemode_agent.cli import ScriptEvaluator, build_agent

    # Record model info as eval attributes
    set_eval_attribute("model_id", inputs.model_id)
    set_eval_attribute("model_label", inputs.model_label)
    if inputs.reasoning_effort is not None:
        set_eval_attribute("reasoning_effort", inputs.reasoning_effort)

    # Build model settings using OpenRouterModelSettings when reasoning is configured
    model_settings = _build_model_settings(inputs)

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
    input_tokens = (usage.input_tokens or 0) if usage else 0
    output_tokens = (usage.output_tokens or 0) if usage else 0

    increment_eval_metric("total_tokens", total_tokens)
    increment_eval_metric("input_tokens", input_tokens)
    increment_eval_metric("output_tokens", output_tokens)

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

    # Fetch actual cost from OpenRouter generation stats API
    # This gives us the real USD cost including cache discounts, etc.
    generation_id = _extract_generation_id(result)
    if generation_id:
        cost = _fetch_generation_cost(generation_id)
        if cost is not None:
            increment_eval_metric("cost_usd", cost)
            set_eval_attribute("cost_source", "openrouter_generation_api")
    else:
        logger.debug("Could not extract generation ID for cost lookup")

    return output


def _build_model_settings(inputs: EvalInputs) -> Any:
    """Build the appropriate ModelSettings for the model provider.

    Uses OpenRouterModelSettings when reasoning effort is configured
    and the model is an OpenRouter model. Falls back to base ModelSettings
    for other providers.
    """
    has_reasoning = inputs.reasoning_effort is not None
    has_extra = bool(inputs.extra_model_settings)

    if not has_reasoning and not has_extra:
        return None

    is_openrouter = inputs.model_id.startswith("openrouter:")

    if is_openrouter and has_reasoning:
        try:
            from pydantic_ai.models.openrouter import OpenRouterModelSettings

            settings_dict: dict[str, Any] = {}
            if inputs.extra_model_settings:
                settings_dict.update(inputs.extra_model_settings)

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
