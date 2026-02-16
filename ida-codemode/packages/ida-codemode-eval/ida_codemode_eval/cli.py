"""CLI entry point for ida-codemode-eval."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from rich.console import Console


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ida-codemode-eval",
        description="Evaluate LLM model performance on IDA reverse engineering tasks",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- run command ---
    run_parser = subparsers.add_parser("run", help="Run evaluation suite")
    run_parser.add_argument(
        "config",
        type=Path,
        help="Path to evaluation config YAML file",
    )
    run_parser.add_argument(
        "--model",
        default=None,
        help="Filter to evaluate only models whose label contains this string",
    )
    run_parser.add_argument(
        "--runs",
        type=int,
        default=None,
        help="Override runs_per_model from config",
    )
    run_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    # --- compare command ---
    compare_parser = subparsers.add_parser("compare", help="Compare two result files")
    compare_parser.add_argument(
        "result_a",
        type=Path,
        help="First result JSON file",
    )
    compare_parser.add_argument(
        "result_b",
        type=Path,
        help="Second result JSON file",
    )

    # --- compare-many command ---
    compare_many_parser = subparsers.add_parser(
        "compare-many", help="Compare multiple result files in a table"
    )
    compare_many_parser.add_argument(
        "results",
        type=Path,
        nargs="+",
        help="Result JSON files to compare",
    )

    # --- plot command ---
    plot_parser = subparsers.add_parser(
        "plot", help="Generate comparison plots (requires matplotlib)"
    )
    plot_parser.add_argument(
        "results",
        type=Path,
        nargs="+",
        help="Result JSON files to plot",
    )
    plot_parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Save plot to file instead of displaying interactively",
    )
    plot_parser.add_argument(
        "--longitudinal",
        action="store_true",
        help="Plot as time series (files should be chronological, same model)",
    )

    # --- list-models command ---
    subparsers.add_parser("list-models", help="List available OpenRouter models")

    return parser


def _cmd_run(args: argparse.Namespace, console: Console) -> int:
    """Execute the 'run' subcommand."""
    from ida_codemode_eval.config import EvalConfig
    from ida_codemode_eval.runner import run_evaluation

    config_path = args.config.resolve()
    if not config_path.exists():
        console.print(f"[red]error:[/red] config file not found: {config_path}")
        return 2

    config = EvalConfig.from_yaml(config_path)

    if args.runs is not None:
        config.runs_per_model = args.runs

    # Initialize Logfire observability
    try:
        from ida_codemode_agent.observability import configure_observability

        configure_observability(model="eval-runner", db_path=config.database)
    except Exception:
        pass

    summaries = asyncio.run(
        run_evaluation(
            config,
            config_dir=config_path.parent,
            console=console,
            model_filter=args.model,
        )
    )

    if not summaries:
        console.print("[yellow]No evaluations completed.[/yellow]")
        return 1

    return 0


def _cmd_compare(args: argparse.Namespace, console: Console) -> int:
    """Execute the 'compare' subcommand."""
    from ida_codemode_eval.runner import compare_results

    path_a = args.result_a.resolve()
    path_b = args.result_b.resolve()

    for path in (path_a, path_b):
        if not path.exists():
            console.print(f"[red]error:[/red] result file not found: {path}")
            return 2

    compare_results(path_a, path_b, console)
    return 0


def _cmd_compare_many(args: argparse.Namespace, console: Console) -> int:
    """Execute the 'compare-many' subcommand."""
    from ida_codemode_eval.compare import compare_many

    paths = [p.resolve() for p in args.results]
    for p in paths:
        if not p.exists():
            console.print(f"[red]error:[/red] result file not found: {p}")
            return 2

    compare_many(paths, console)
    return 0


def _cmd_plot(args: argparse.Namespace, console: Console) -> int:
    """Execute the 'plot' subcommand."""
    paths = [p.resolve() for p in args.results]
    for p in paths:
        if not p.exists():
            console.print(f"[red]error:[/red] result file not found: {p}")
            return 2

    try:
        if args.longitudinal:
            from ida_codemode_eval.compare import plot_longitudinal

            plot_longitudinal(paths, output_path=args.output)
        else:
            from ida_codemode_eval.compare import plot_comparison

            plot_comparison(paths, output_path=args.output)
    except ImportError as exc:
        console.print(f"[red]error:[/red] {exc}")
        return 2

    if args.output:
        console.print(f"[green]Plot saved to:[/green] {args.output}")
    return 0


def _cmd_list_models(console: Console) -> int:
    """Execute the 'list-models' subcommand."""
    try:
        from ida_codemode_agent.cli import _available_models

        models = _available_models()
    except Exception as exc:
        console.print(f"[red]error:[/red] failed to fetch models: {exc}")
        return 2

    console.print(f"[bold]Available models ({len(models)}):[/bold]")
    for model_name in models:
        console.print(f"  {model_name}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    console = Console()

    if args.command is None:
        parser.print_help()
        return 2

    if hasattr(args, "verbose"):
        _configure_logging(args.verbose)

    if args.command == "run":
        return _cmd_run(args, console)
    elif args.command == "compare":
        return _cmd_compare(args, console)
    elif args.command == "compare-many":
        return _cmd_compare_many(args, console)
    elif args.command == "plot":
        return _cmd_plot(args, console)
    elif args.command == "list-models":
        return _cmd_list_models(console)
    else:
        parser.print_help()
        return 2


if __name__ == "__main__":
    sys.exit(main())
