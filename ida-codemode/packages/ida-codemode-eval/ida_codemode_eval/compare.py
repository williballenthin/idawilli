"""Result comparison and longitudinal analysis utilities.

Load saved evaluation results and compare across models, runs, or time periods.
Optionally generate plots when matplotlib is available.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table


def load_result(path: Path) -> dict[str, Any]:
    """Load a saved evaluation result JSON file."""
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _extract_metrics(data: dict[str, Any]) -> dict[str, Any]:
    """Extract summary metrics from a result file."""
    cases = data.get("cases", [])
    if not cases:
        return {"total": 0}

    successes = 0
    durations: list[float] = []
    tokens: list[float] = []
    turns: list[float] = []
    tool_calls: list[float] = []

    for c in cases:
        assertions = c.get("assertions", {})
        if assertions.get("ContainsC2Indicator") is True:
            successes += 1
        if c.get("duration") is not None:
            durations.append(float(c["duration"]))
        scores = c.get("scores", {})
        if "TokenUsage" in scores:
            tokens.append(float(scores["TokenUsage"]))
        if "TurnCount" in scores:
            turns.append(float(scores["TurnCount"]))
        if "ToolCallCount" in scores:
            tool_calls.append(float(scores["ToolCallCount"]))

    total = len(cases)

    def _stats(values: list[float]) -> dict[str, float]:
        if not values:
            return {"mean": 0, "min": 0, "max": 0, "stddev": 0}
        mean = sum(values) / len(values)
        if len(values) > 1:
            variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
            stddev = variance**0.5
        else:
            stddev = 0.0
        return {"mean": mean, "min": min(values), "max": max(values), "stddev": stddev}

    return {
        "model_label": data.get("model_label", "unknown"),
        "timestamp": data.get("timestamp", "unknown"),
        "total": total,
        "successes": successes,
        "success_rate": successes / total if total > 0 else 0.0,
        "duration": _stats(durations),
        "tokens": _stats(tokens),
        "turns": _stats(turns),
        "tool_calls": _stats(tool_calls),
    }


def compare_many(
    paths: list[Path], console: Console | None = None
) -> list[dict[str, Any]]:
    """Compare multiple result files in a single table.

    Args:
        paths: List of result JSON file paths.
        console: Rich console for output.

    Returns:
        List of extracted metrics dicts.
    """
    if console is None:
        console = Console()

    all_metrics = []
    for p in paths:
        data = load_result(p)
        metrics = _extract_metrics(data)
        metrics["file"] = p.name
        all_metrics.append(metrics)

    table = Table(title="Evaluation Comparison", show_lines=True)
    table.add_column("File", style="dim", max_width=40)
    table.add_column("Model", style="bold")
    table.add_column("Timestamp")
    table.add_column("Runs", justify="right")
    table.add_column("Success", justify="right")
    table.add_column("Avg Duration", justify="right")
    table.add_column("Avg Tokens", justify="right")
    table.add_column("Avg Turns", justify="right")
    table.add_column("Avg Tools", justify="right")

    for m in all_metrics:
        table.add_row(
            m["file"],
            m["model_label"],
            m["timestamp"],
            str(m["total"]),
            f"{m['success_rate']:.0%} ({m['successes']}/{m['total']})",
            f"{m['duration']['mean']:.1f}s",
            f"{m['tokens']['mean']:.0f}",
            f"{m['turns']['mean']:.1f}",
            f"{m['tool_calls']['mean']:.1f}",
        )

    console.print(table)
    return all_metrics


def plot_comparison(
    paths: list[Path],
    output_path: Path | None = None,
) -> None:
    """Generate comparison plots from multiple result files.

    Creates a multi-panel figure comparing success rate, duration, tokens,
    and turns across all result files. Requires matplotlib.

    Args:
        paths: List of result JSON file paths.
        output_path: Where to save the plot. If None, displays interactively.
    """
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        raise ImportError(
            "matplotlib is required for plotting. Install it with: "
            "pip install matplotlib"
        )

    all_metrics = []
    for p in paths:
        data = load_result(p)
        metrics = _extract_metrics(data)
        metrics["file"] = p.name
        all_metrics.append(metrics)

    labels = [f"{m['model_label']}\n{m['timestamp']}" for m in all_metrics]

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle("Model Evaluation Comparison", fontsize=14, fontweight="bold")

    # Success Rate
    ax = axes[0][0]
    rates = [m["success_rate"] * 100 for m in all_metrics]
    bars = ax.bar(range(len(labels)), rates, color="steelblue")
    ax.set_ylabel("Success Rate (%)")
    ax.set_title("Success Rate")
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
    ax.set_ylim(0, 105)
    for bar, rate in zip(bars, rates):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 1,
            f"{rate:.0f}%",
            ha="center",
            va="bottom",
            fontsize=8,
        )

    # Duration
    ax = axes[0][1]
    means = [m["duration"]["mean"] for m in all_metrics]
    stds = [m["duration"]["stddev"] for m in all_metrics]
    ax.bar(range(len(labels)), means, yerr=stds, color="coral", capsize=4)
    ax.set_ylabel("Duration (seconds)")
    ax.set_title("Average Duration")
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)

    # Token Usage
    ax = axes[1][0]
    means = [m["tokens"]["mean"] for m in all_metrics]
    stds = [m["tokens"]["stddev"] for m in all_metrics]
    ax.bar(range(len(labels)), means, yerr=stds, color="mediumpurple", capsize=4)
    ax.set_ylabel("Total Tokens")
    ax.set_title("Average Token Usage")
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)

    # Turns
    ax = axes[1][1]
    means = [m["turns"]["mean"] for m in all_metrics]
    stds = [m["turns"]["stddev"] for m in all_metrics]
    ax.bar(range(len(labels)), means, yerr=stds, color="seagreen", capsize=4)
    ax.set_ylabel("Turns")
    ax.set_title("Average Agent Turns")
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)

    plt.tight_layout()

    if output_path:
        plt.savefig(str(output_path), dpi=150, bbox_inches="tight")
    else:
        plt.show()


def plot_longitudinal(
    paths: list[Path],
    output_path: Path | None = None,
) -> None:
    """Plot metrics over time for the same model across multiple eval runs.

    Useful for tracking how prompt/tool changes affect performance over time.
    Paths should be sorted chronologically.

    Args:
        paths: List of result JSON file paths (chronological order).
        output_path: Where to save the plot. If None, displays interactively.
    """
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        raise ImportError(
            "matplotlib is required for plotting. Install it with: "
            "pip install matplotlib"
        )

    all_metrics = []
    for p in paths:
        data = load_result(p)
        metrics = _extract_metrics(data)
        metrics["file"] = p.name
        all_metrics.append(metrics)

    timestamps = [m["timestamp"] for m in all_metrics]
    x = range(len(timestamps))

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    model_label = all_metrics[0]["model_label"] if all_metrics else "Unknown"
    fig.suptitle(f"Longitudinal: {model_label}", fontsize=14, fontweight="bold")

    # Success Rate over time
    ax = axes[0][0]
    rates = [m["success_rate"] * 100 for m in all_metrics]
    ax.plot(x, rates, "o-", color="steelblue", linewidth=2, markersize=8)
    ax.set_ylabel("Success Rate (%)")
    ax.set_title("Success Rate Over Time")
    ax.set_xticks(list(x))
    ax.set_xticklabels(timestamps, rotation=45, ha="right", fontsize=8)
    ax.set_ylim(0, 105)

    # Duration over time
    ax = axes[0][1]
    means = [m["duration"]["mean"] for m in all_metrics]
    stds = [m["duration"]["stddev"] for m in all_metrics]
    ax.errorbar(
        list(x),
        means,
        yerr=stds,
        fmt="o-",
        color="coral",
        linewidth=2,
        markersize=8,
        capsize=4,
    )
    ax.set_ylabel("Duration (s)")
    ax.set_title("Duration Over Time")
    ax.set_xticks(list(x))
    ax.set_xticklabels(timestamps, rotation=45, ha="right", fontsize=8)

    # Tokens over time
    ax = axes[1][0]
    means = [m["tokens"]["mean"] for m in all_metrics]
    stds = [m["tokens"]["stddev"] for m in all_metrics]
    ax.errorbar(
        list(x),
        means,
        yerr=stds,
        fmt="o-",
        color="mediumpurple",
        linewidth=2,
        markersize=8,
        capsize=4,
    )
    ax.set_ylabel("Total Tokens")
    ax.set_title("Token Usage Over Time")
    ax.set_xticks(list(x))
    ax.set_xticklabels(timestamps, rotation=45, ha="right", fontsize=8)

    # Turns over time
    ax = axes[1][1]
    means = [m["turns"]["mean"] for m in all_metrics]
    stds = [m["turns"]["stddev"] for m in all_metrics]
    ax.errorbar(
        list(x),
        means,
        yerr=stds,
        fmt="o-",
        color="seagreen",
        linewidth=2,
        markersize=8,
        capsize=4,
    )
    ax.set_ylabel("Turns")
    ax.set_title("Turns Over Time")
    ax.set_xticks(list(x))
    ax.set_xticklabels(timestamps, rotation=45, ha="right", fontsize=8)

    plt.tight_layout()

    if output_path:
        plt.savefig(str(output_path), dpi=150, bbox_inches="tight")
    else:
        plt.show()
