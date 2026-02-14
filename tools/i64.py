# /// script
# requires-python = ">=3.10"
# dependencies = ["ida-domain", "rich"]
# ///
"""Create an IDA .i64 database from a binary file."""

from __future__ import annotations

import argparse
import logging
import sys
import tempfile
from contextlib import nullcontext
from pathlib import Path
from time import perf_counter

from rich.console import Console
from rich.logging import RichHandler

logger = logging.getLogger(__name__)

stderr_console = Console(stderr=True)
stdout_console = Console()


def configure_logging(verbose: bool, quiet: bool) -> None:
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=stderr_console, show_path=False)],
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create an IDA .i64 database from a binary file.",
    )
    parser.add_argument("file", type=Path, help="path to binary file (exe, dll, so, etc.)")
    parser.add_argument("--thorough", action="store_true", help="decompile all functions to cache pseudocode")
    parser.add_argument("--verbose", action="store_true", help="enable debug logging")
    parser.add_argument("--quiet", action="store_true", help="suppress status output")
    return parser


def decompile_all() -> None:
    """Decompile all functions to cache pseudocode in the database.

    Must be called while a Database context is open.

    Raises:
        RuntimeError: If the decompiler is unavailable or fails.
    """
    import ida_hexrays

    with tempfile.NamedTemporaryFile(suffix=".c", delete=True) as tmp:
        tmp_path = tmp.name

    ida_hexrays.decompile_many(
        tmp_path,
        None,
        ida_hexrays.VDRUN_NEWFILE | ida_hexrays.VDRUN_SILENT | ida_hexrays.VDRUN_MAYSTOP,
    )

    tmp_file = Path(tmp_path)
    if tmp_file.exists():
        tmp_file.unlink()
        logger.debug("cleaned up temp decompilation output: %s", tmp_path)


def create_database(input_path: Path, thorough: bool, quiet: bool) -> Path:
    """Open a binary with IDA, run auto-analysis, and save a compressed .i64.

    Raises:
        RuntimeError: If IDA fails to analyze the file.
    """
    from ida_domain import Database
    from ida_domain.database import IdaCommandOptions

    options = IdaCommandOptions(
        auto_analysis=True,
        new_database=True,
        db_compression="compress",
    )

    output_path = input_path.parent / (input_path.name + ".i64")

    ctx = stderr_console.status(f"Analyzing {input_path.name}...", spinner="dots") if not quiet else nullcontext()
    with ctx as status:
        with Database.open(str(input_path), options, save_on_close=True) as db:
            logger.debug("database opened: %s", input_path)
            logger.debug("architecture: %s", db.architecture)
            logger.debug("functions: %d", len(db.functions))

            if thorough:
                if status is not None:
                    status.update("Decompiling all functions...", spinner="bouncingBall")
                decompile_all()

    return output_path


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    configure_logging(args.verbose, args.quiet)

    input_path: Path = args.file.resolve()

    if not input_path.is_file():
        stdout_console.print(f"[red]error:[/red] file not found: {input_path}")
        return 1

    output_path = input_path.parent / (input_path.name + ".i64")

    if output_path.exists():
        stdout_console.print(f"[red]error:[/red] database already exists: {output_path}")
        return 1

    start_time = perf_counter()

    try:
        result = create_database(input_path, args.thorough, args.quiet)
        elapsed = perf_counter() - start_time
        stdout_console.print(f"[green]{result}[/green]")
        stdout_console.print(f"[cyan]total time:[/cyan] {elapsed:.2f}s")
        return 0
    except Exception:
        logger.debug("analysis failed", exc_info=True)
        stdout_console.print(f"[red]error:[/red] failed to analyze: {input_path}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
