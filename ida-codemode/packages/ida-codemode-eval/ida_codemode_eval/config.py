"""Evaluation configuration schema.

Defines the typed configuration for evaluation runs, loaded from YAML.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

# OpenRouter reasoning effort levels.
# See https://openrouter.ai/docs/guides/best-practices/reasoning-tokens
ReasoningEffort = Literal["xhigh", "high", "medium", "low", "minimal", "none"]


@dataclass
class ModelConfig:
    """Configuration for a single model to evaluate."""

    id: str
    """Model identifier in provider:model format (e.g. openrouter:anthropic/claude-sonnet-4-20250514)."""

    label: str
    """Human-readable label used in reports and result filenames."""

    reasoning_effort: ReasoningEffort | None = None
    """Optional reasoning effort level for models that support thinking.

    OpenRouter effort levels: xhigh, high, medium, low, minimal, none.
    Maps to OpenRouter's ``reasoning.effort`` parameter.
    None means no reasoning configuration is sent (model default).
    """

    model_settings: dict[str, Any] = field(default_factory=dict)
    """Additional pydantic-ai ModelSettings passed to agent.run()."""


@dataclass
class EvalConfig:
    """Top-level evaluation configuration."""

    name: str
    """Name for this evaluation suite (used in Logfire experiment names)."""

    database: str
    """Path to the IDA database or binary to analyze.

    Relative paths are resolved from the eval config file's directory.
    """

    task_prompt: str
    """The prompt sent to the agent for each evaluation run."""

    magic_string: str
    """The C2 indicator string that must appear in the agent output for success."""

    models: list[ModelConfig]
    """Model configurations to evaluate."""

    runs_per_model: int = 5
    """Number of times to run each model+config combination."""

    timeout_per_run: float = 300.0
    """Maximum wall-clock seconds per single agent run."""

    max_concurrency: int = 1
    """Maximum concurrent evaluations.

    Each trial copies the IDA database to a temporary directory, so higher
    values are safe.  The main benefit of concurrency > 1 is overlapping LLM
    API round-trips while one trial waits for a model response.  Note that
    idalib requires main-thread access; tool callbacks are async so they
    execute on the event-loop thread (the main thread under ``asyncio.run``),
    and the synchronous ``sandbox.run()`` call naturally serializes database
    access even when multiple coroutines are in flight.
    """

    system_prompt: str | None = None
    """Optional system prompt override. Uses the agent default if None."""

    @staticmethod
    def from_yaml(path: str | Path) -> EvalConfig:
        """Load an evaluation config from a YAML file."""
        config_path = Path(path)
        with config_path.open("r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        if not isinstance(raw, dict):
            raise ValueError(f"expected a YAML mapping in {config_path}, got {type(raw).__name__}")

        models = []
        for m in raw.get("models", []):
            models.append(ModelConfig(
                id=m["id"],
                label=m["label"],
                reasoning_effort=m.get("reasoning_effort"),
                model_settings=m.get("model_settings", {}),
            ))

        return EvalConfig(
            name=raw.get("name", config_path.stem),
            database=raw["database"],
            task_prompt=raw["task_prompt"],
            magic_string=raw["magic_string"],
            models=models,
            runs_per_model=raw.get("runs_per_model", 5),
            timeout_per_run=raw.get("timeout_per_run", 300.0),
            max_concurrency=raw.get("max_concurrency", 1),
            system_prompt=raw.get("system_prompt"),
        )

    def resolve_database_path(self, config_dir: Path) -> Path:
        """Resolve the database path relative to the config file directory."""
        db_path = Path(self.database)
        if db_path.is_absolute():
            return db_path
        return (config_dir / db_path).resolve()
