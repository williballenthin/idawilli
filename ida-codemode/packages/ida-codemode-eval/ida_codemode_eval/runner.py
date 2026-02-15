"""Evaluation runner.

Orchestrates evaluation of multiple models across repeated runs,
building pydantic-evals datasets and collecting results.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic_evals import Case, Dataset
from pydantic_evals.evaluators import MaxDuration
from rich.console import Console

from ida_codemode_eval.config import EvalConfig, ModelConfig
from ida_codemode_eval.evaluators import (
    ContainsC2Indicator,
    EstimatedCost,
    RequestTokens,
    ResponseTokens,
    TokenUsage,
    ToolCallCount,
    TurnCount,
)
from ida_codemode_eval.task import EvalInputs, run_eval_task

logger = logging.getLogger(__name__)


def _build_dataset_for_model(
    *,
    config: EvalConfig,
    model_config: ModelConfig,
    sandbox: Any,
) -> Dataset[EvalInputs, str, dict[str, Any]]:
    """Build a pydantic-evals Dataset for one model configuration.

    Creates N cases (one per run) all using the same model+prompt+config,
    so pydantic-evals can run them and we get N data points for statistics.
    """
    cases: list[Case[EvalInputs, str, dict[str, Any]]] = []

    for run_idx in range(config.runs_per_model):
        inputs = EvalInputs(
            prompt=config.task_prompt,
            model_id=model_config.id,
            model_label=model_config.label,
            thinking_budget=model_config.thinking_budget,
            extra_model_settings=model_config.model_settings or None,
            sandbox=sandbox,
            system_prompt_override=config.system_prompt,
        )

        cases.append(Case(
            name=f"{model_config.label}/run-{run_idx:02d}",
            inputs=inputs,
            expected_output=None,
            metadata={
                "magic_string": config.magic_string,
                "model_id": model_config.id,
                "model_label": model_config.label,
                "run_index": run_idx,
                "thinking_budget": model_config.thinking_budget,
            },
        ))

    evaluators: list[Any] = [
        ContainsC2Indicator(),
        MaxDuration(seconds=config.timeout_per_run),
        TokenUsage(),
        RequestTokens(),
        ResponseTokens(),
        TurnCount(),
        ToolCallCount(),
        EstimatedCost(),
    ]

    return Dataset(cases=cases, evaluators=evaluators)


def _results_dir(base_dir: Path) -> Path:
    """Return the results directory, creating it if needed."""
    results = base_dir / "results"
    results.mkdir(parents=True, exist_ok=True)
    return results


def _save_report(
    report: Any,
    model_label: str,
    results_dir: Path,
) -> Path:
    """Save an evaluation report as a JSON file for longitudinal comparison.

    Returns the path to the saved file.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_label = model_label.replace("/", "_").replace(":", "_")
    filename = f"{timestamp}_{safe_label}.json"
    filepath = results_dir / filename

    # Extract serializable data from the report
    report_data: dict[str, Any] = {
        "timestamp": timestamp,
        "model_label": model_label,
        "cases": [],
    }

    if hasattr(report, "cases"):
        for case in report.cases:
            case_data: dict[str, Any] = {
                "name": getattr(case, "name", ""),
                "success": None,
                "duration": None,
                "scores": {},
                "labels": {},
                "assertions": {},
            }

            if hasattr(case, "scores"):
                for k, v in case.scores.items():
                    case_data["scores"][k] = v
            if hasattr(case, "labels"):
                for k, v in case.labels.items():
                    case_data["labels"][k] = v
            if hasattr(case, "assertions"):
                for k, v in case.assertions.items():
                    case_data["assertions"][k] = v
            if hasattr(case, "duration"):
                case_data["duration"] = case.duration

            report_data["cases"].append(case_data)

    filepath.write_text(json.dumps(report_data, indent=2, default=str), encoding="utf-8")
    return filepath


def _compute_summary(report: Any, model_label: str) -> dict[str, Any]:
    """Compute aggregate statistics from an evaluation report."""
    summary: dict[str, Any] = {
        "model_label": model_label,
        "total_runs": 0,
        "successful_runs": 0,
        "success_rate": 0.0,
        "durations": [],
        "total_tokens": [],
        "turns": [],
        "tool_calls": [],
    }

    if not hasattr(report, "cases"):
        return summary

    for case in report.cases:
        summary["total_runs"] += 1

        if hasattr(case, "assertions"):
            c2_result = case.assertions.get("ContainsC2Indicator")
            if c2_result is True:
                summary["successful_runs"] += 1

        if hasattr(case, "duration") and case.duration is not None:
            summary["durations"].append(case.duration)

        if hasattr(case, "scores"):
            if "TokenUsage" in case.scores:
                summary["total_tokens"].append(case.scores["TokenUsage"])
            if "TurnCount" in case.scores:
                summary["turns"].append(case.scores["TurnCount"])
            if "ToolCallCount" in case.scores:
                summary["tool_calls"].append(case.scores["ToolCallCount"])

    total = summary["total_runs"]
    if total > 0:
        summary["success_rate"] = summary["successful_runs"] / total

    return summary


def _print_summary(summary: dict[str, Any], console: Console) -> None:
    """Print aggregate statistics for one model configuration."""
    from rich.table import Table

    table = Table(title=f"Summary: {summary['model_label']}", show_lines=True)
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    total = summary["total_runs"]
    success = summary["successful_runs"]
    rate = summary["success_rate"]
    table.add_row("Runs", str(total))
    table.add_row("Successes", f"{success}/{total}")
    table.add_row("Success Rate", f"{rate:.0%}")

    def _stats_row(label: str, values: list[float]) -> None:
        if not values:
            table.add_row(label, "n/a")
            return
        avg = sum(values) / len(values)
        mn = min(values)
        mx = max(values)
        if len(values) > 1:
            variance = sum((v - avg) ** 2 for v in values) / (len(values) - 1)
            stddev = variance**0.5
            table.add_row(label, f"avg={avg:.1f}  std={stddev:.1f}  min={mn:.1f}  max={mx:.1f}")
        else:
            table.add_row(label, f"{avg:.1f}")

    _stats_row("Duration (s)", summary["durations"])
    _stats_row("Total Tokens", summary["total_tokens"])
    _stats_row("Turns", summary["turns"])
    _stats_row("Tool Calls", summary["tool_calls"])

    console.print(table)


async def run_evaluation(
    config: EvalConfig,
    *,
    config_dir: Path,
    console: Console | None = None,
    model_filter: str | None = None,
) -> list[dict[str, Any]]:
    """Run the full evaluation matrix.

    Args:
        config: The evaluation configuration.
        config_dir: Directory containing the config file (for resolving relative paths).
        console: Rich console for output. Creates a default if None.
        model_filter: If set, only evaluate models whose label contains this string.

    Returns:
        List of summary dicts, one per model configuration.
    """
    if console is None:
        console = Console()

    db_path = config.resolve_database_path(config_dir)
    console.print(f"[bold]Database:[/bold] {db_path}")
    console.print(f"[bold]Runs per model:[/bold] {config.runs_per_model}")
    console.print(f"[bold]Magic string:[/bold] {config.magic_string}")
    console.print()

    # Open the IDA database once for the entire evaluation
    from ida_codemode_sandbox import IdaSandbox
    from ida_domain import Database
    from ida_domain.database import IdaCommandOptions

    ida_options = IdaCommandOptions(auto_analysis=True, new_database=False)
    db_cm = Database.open(str(db_path), ida_options, save_on_close=False)
    db = db_cm.__enter__()

    results_dir = _results_dir(config_dir)
    summaries: list[dict[str, Any]] = []

    try:
        sandbox = IdaSandbox(db)

        models_to_eval = config.models
        if model_filter:
            models_to_eval = [m for m in models_to_eval if model_filter in m.label]
            if not models_to_eval:
                console.print(f"[yellow]No models match filter '{model_filter}'[/yellow]")
                return []

        for model_config in models_to_eval:
            console.print(f"\n[bold cyan]Evaluating: {model_config.label}[/bold cyan]")
            console.print(f"  Model: {model_config.id}")
            if model_config.thinking_budget is not None:
                console.print(f"  Thinking budget: {model_config.thinking_budget}")
            console.print()

            dataset = _build_dataset_for_model(
                config=config,
                model_config=model_config,
                sandbox=sandbox,
            )

            experiment_name = f"{config.name}/{model_config.label}"
            report = await dataset.evaluate(
                run_eval_task,
                name=experiment_name,
                max_concurrency=config.max_concurrency,
            )

            report.print()

            saved_path = _save_report(report, model_config.label, results_dir)
            console.print(f"\n[dim]Results saved to: {saved_path}[/dim]")

            summary = _compute_summary(report, model_config.label)
            summaries.append(summary)
            _print_summary(summary, console)

    finally:
        db_cm.__exit__(None, None, None)

    # Print overall comparison table
    if len(summaries) > 1:
        _print_comparison(summaries, console)

    return summaries


def _print_comparison(summaries: list[dict[str, Any]], console: Console) -> None:
    """Print a side-by-side comparison table of all evaluated models."""
    from rich.table import Table

    table = Table(title="Model Comparison", show_lines=True)
    table.add_column("Model", style="bold")
    table.add_column("Success Rate", justify="right")
    table.add_column("Avg Duration (s)", justify="right")
    table.add_column("Avg Tokens", justify="right")
    table.add_column("Avg Turns", justify="right")
    table.add_column("Avg Tool Calls", justify="right")

    for s in sorted(summaries, key=lambda x: x["success_rate"], reverse=True):
        def _avg(values: list[float]) -> str:
            if not values:
                return "n/a"
            return f"{sum(values) / len(values):.1f}"

        table.add_row(
            s["model_label"],
            f"{s['success_rate']:.0%}",
            _avg(s["durations"]),
            _avg(s["total_tokens"]),
            _avg(s["turns"]),
            _avg(s["tool_calls"]),
        )

    console.print()
    console.print(table)


def compare_results(path_a: Path, path_b: Path, console: Console | None = None) -> None:
    """Compare two saved evaluation result files side by side.

    Useful for longitudinal comparison (e.g., before/after a prompt change).
    """
    if console is None:
        console = Console()

    with path_a.open("r", encoding="utf-8") as f:
        data_a = json.load(f)
    with path_b.open("r", encoding="utf-8") as f:
        data_b = json.load(f)

    from rich.table import Table

    table = Table(title="Result Comparison", show_lines=True)
    table.add_column("Metric", style="bold")
    table.add_column(f"A: {path_a.name}", justify="right")
    table.add_column(f"B: {path_b.name}", justify="right")
    table.add_column("Delta", justify="right")

    def _extract_stats(data: dict[str, Any]) -> dict[str, float]:
        cases = data.get("cases", [])
        if not cases:
            return {}

        successes = 0
        durations: list[float] = []
        tokens: list[float] = []

        for c in cases:
            assertions = c.get("assertions", {})
            if assertions.get("ContainsC2Indicator") is True:
                successes += 1
            if c.get("duration") is not None:
                durations.append(float(c["duration"]))
            scores = c.get("scores", {})
            if "TokenUsage" in scores:
                tokens.append(float(scores["TokenUsage"]))

        total = len(cases)
        return {
            "success_rate": successes / total if total > 0 else 0.0,
            "avg_duration": sum(durations) / len(durations) if durations else 0.0,
            "avg_tokens": sum(tokens) / len(tokens) if tokens else 0.0,
        }

    stats_a = _extract_stats(data_a)
    stats_b = _extract_stats(data_b)

    for metric in ["success_rate", "avg_duration", "avg_tokens"]:
        va = stats_a.get(metric, 0.0)
        vb = stats_b.get(metric, 0.0)
        delta = vb - va
        sign = "+" if delta >= 0 else ""

        if metric == "success_rate":
            table.add_row(metric, f"{va:.0%}", f"{vb:.0%}", f"{sign}{delta:.0%}")
        else:
            table.add_row(metric, f"{va:.1f}", f"{vb:.1f}", f"{sign}{delta:.1f}")

    console.print(table)
