"""Logfire observability for ida-codemode-agent.

Provides centralized instrumentation setup.  When a Logfire write-token is
available the SDK sends spans/metrics to Logfire; otherwise it silently
does nothing so the agent works normally without any observability backend.
"""

from __future__ import annotations

import logfire


def configure_observability(*, model: str, db_path: str) -> None:
    """Initialize Logfire instrumentation.

    Safe to call even without a Logfire token — ``send_to_logfire="if-token-present"``
    makes the SDK skip exporting when no credentials are found.

    Args:
        model: The LLM model identifier (e.g. ``"openrouter:google/gemini-3-flash-preview"``).
        db_path: Path to the IDA database being analyzed.
    """
    # Disable Logfire's local console renderer so span names/events don't pollute
    # the interactive CLI output stream.
    logfire.configure(
        service_name="ida-codemode-agent",
        send_to_logfire="if-token-present",
        console=False,
        inspect_arguments=False,
        metrics=logfire.MetricsOptions(additional_readers=[]),
    )

    # Automatic pydantic-ai instrumentation: creates spans for agent runs,
    # model requests, tool calls, and records token-usage metrics.
    logfire.instrument_pydantic_ai()

    # HTTP-level spans for outgoing requests (LLM API calls via OpenRouter, etc.)
    try:
        logfire.instrument_httpx()
    except Exception:
        # httpx instrumentation is optional; don't block startup if it fails.
        pass
