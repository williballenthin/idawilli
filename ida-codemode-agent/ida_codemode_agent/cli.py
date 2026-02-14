#!/usr/bin/env python3
"""CLI for ida-codemode-agent."""

from __future__ import annotations

import argparse
import ast
import codecs
import json
import logging
import math
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import cache
from pathlib import Path
from typing import Any, Callable, Literal, cast, get_args

from rich.columns import Columns
from rich.console import Console, Group, RenderableType
from rich.markdown import Markdown
from rich.panel import Panel
from rich.pretty import Pretty
from rich.rule import Rule
from rich.spinner import Spinner
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

DEFAULT_MODEL = os.getenv("IDA_CODEMODE_AGENT_MODEL", "google/gemini-3-flash-preview")
DEFAULT_PROVIDER = os.getenv("IDA_CODEMODE_AGENT_PROVIDER", "openrouter")
IDB_EXTENSIONS = {".i64", ".idb"}

BASE_SYSTEM_PROMPT = """
You are an expert reverse engineering assistant operating on a single opened IDA database.

You have one tool: `evaluate_ida_script`.
Use it to execute sandboxed Python code against the database.

Rules:
- Ground claims in tool output; do not guess.
- Scripts run in a sandbox: do not use `import`, `sys`, `os`, `open`, network, or subprocess access.
- Use short, focused scripts; prefer iterative discovery over one giant script.
- Prefer `decompile_function_at(...)` pseudocode over raw disassembly for understanding logic; it is usually more concise and more informative.
- For likely-success API calls, prefer `expect_ok(...)`; for every `x = expect_ok(...)`, guard with `if x is not None:` before any `x[...]` access.
- Safe template: `r = expect_ok(api_call(...))`; then `if r is None: ... else: use r[...]`.
- For explicit failure branches, use `is_error(payload)` (avoid `"error" in payload` for type narrowing).
- If a callback shape is unclear, call `help("callback_name")` first.
- If a tool run fails with typing errors, send a minimal follow-up script that only fixes the reported type issue.
- In final responses, include concrete evidence (addresses, names, snippets).
""".strip()


def _resolve_model_name(model: str, provider: str) -> str:
    if ":" in model:
        return model
    return f"{provider}:{model}"


@cache
def _openrouter_model_ids() -> tuple[str, ...]:
    """Fetch model IDs from OpenRouter's public models endpoint."""
    import httpx

    headers: dict[str, str] = {}
    api_key = os.getenv("OPENROUTER_API_KEY")
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    response = httpx.get("https://openrouter.ai/api/v1/models", headers=headers, timeout=15.0)
    response.raise_for_status()

    payload = response.json()
    data = payload.get("data", [])
    if not isinstance(data, list):
        return tuple()

    models: set[str] = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        model_id = item.get("id")
        if isinstance(model_id, str) and model_id:
            models.add(f"openrouter:{model_id}")

    return tuple(sorted(models))


def _available_models() -> list[str]:
    """Return known model identifiers (plus OpenRouter models when available)."""
    from pydantic_ai.models import KnownModelName

    literal = getattr(KnownModelName, "__value__", KnownModelName)
    models = {name for name in get_args(literal) if isinstance(name, str)}

    # Keep the configured default visible even when provider catalogs are dynamic.
    models.add(_resolve_model_name(DEFAULT_MODEL, DEFAULT_PROVIDER))

    try:
        models.update(_openrouter_model_ids())
    except Exception:
        # Network access can fail/offline; keep the static model list available.
        pass

    return sorted(models)


def _validate_model_name(model: str) -> None:
    """Validate that the given provider:model reference can be instantiated."""
    from pydantic_ai.models import infer_model

    infer_model(model)

    if not model.startswith("openrouter:"):
        return

    try:
        openrouter_models = set(_openrouter_model_ids())
    except Exception as exc:
        raise ValueError(f"failed to verify OpenRouter model catalog: {exc}") from exc

    if model not in openrouter_models:
        raise ValueError(
            f"unknown OpenRouter model '{model}'. "
            "Use --list-models to inspect available OpenRouter model IDs."
        )


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    omitted = len(text) - max_chars
    return f"{text[:max_chars]}\n\n...[truncated {omitted} chars]"


def _configure_logging() -> None:
    """Silence noisy transport-level logs in interactive CLI output."""
    for logger_name in ("httpx", "httpcore"):
        logging.getLogger(logger_name).setLevel(logging.WARNING)


def _cache_root() -> Path:
    raw = os.getenv("XDG_CACHE_DIR") or os.getenv("XDG_CACHE_HOME")
    if raw:
        return Path(raw).expanduser()
    return Path.home() / ".cache"


def _sessions_dir() -> Path:
    return _cache_root() / "Hex-Rays" / "codemode" / "sessions"


class SessionLogger:
    """Append-only JSONL session logger."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("a", encoding="utf-8")

    @classmethod
    def create_default(cls) -> "SessionLogger":
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"{stamp}-{os.getpid()}.jsonl"
        return cls(_sessions_dir() / filename)

    def log(self, event: str, **payload: Any) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **payload,
        }
        self._handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._handle.flush()

    def close(self) -> None:
        self._handle.close()


@dataclass
class DatabaseOpenPlan:
    open_path: Path
    output_database: str | None = None
    creates_database: bool = False


def _binary_companion_databases(binary_path: Path) -> list[Path]:
    return [
        binary_path.with_name(binary_path.name + ".i64"),
        binary_path.with_name(binary_path.name + ".idb"),
    ]


def resolve_database_plan(input_path: Path) -> DatabaseOpenPlan:
    """Resolve how to open/create the IDA database from user input."""
    path = input_path.expanduser()
    suffix = path.suffix.lower()

    if suffix in IDB_EXTENSIONS:
        if path.exists():
            return DatabaseOpenPlan(open_path=path)

        binary_candidate = path.with_suffix("")
        if binary_candidate.exists():
            return DatabaseOpenPlan(
                open_path=binary_candidate,
                output_database=str(path),
                creates_database=True,
            )

        raise FileNotFoundError(
            f"database does not exist: {path} (and no matching binary at {binary_candidate})"
        )

    if not path.exists():
        raise FileNotFoundError(f"file does not exist: {path}")

    for candidate in _binary_companion_databases(path):
        if candidate.exists():
            return DatabaseOpenPlan(open_path=candidate)

    create_target = path.with_name(path.name + ".i64")
    return DatabaseOpenPlan(
        open_path=path,
        output_database=str(create_target),
        creates_database=True,
    )


@dataclass
class ScriptEvaluator:
    sandbox: Any
    max_script_chars: int = 20_000
    max_output_chars: int = 24_000
    on_evaluation: Callable[[str, str], None] | None = None

    def _finalize(self, source: str, tool_result: str) -> str:
        if self.on_evaluation is not None:
            self.on_evaluation(source, tool_result)
        return tool_result

    def evaluate(self, script: str) -> str:
        source = script.strip()
        if not source:
            return self._finalize(source, "status: error\nmessage: empty script")

        if len(source) > self.max_script_chars:
            return self._finalize(
                source,
                (
                    "status: error\n"
                    f"message: script too large ({len(source)} chars), "
                    f"max is {self.max_script_chars}"
                ),
            )

        result = self.sandbox.run(source)
        stdout = "".join(result.stdout)
        stderr = "".join(result.stderr)

        if result.ok:
            out: list[str] = ["status: ok"]
            if stdout:
                out.extend(["stdout:", _truncate(stdout, self.max_output_chars)])
            if stderr:
                out.extend(["stderr:", _truncate(stderr, self.max_output_chars)])
            if result.output is not None:
                out.extend(["result:", _truncate(repr(result.output), self.max_output_chars)])
            if len(out) == 1:
                out.append("no stdout/stderr/result")
            return self._finalize(source, "\n".join(out))

        error = result.error
        if error is None:
            return self._finalize(source, "status: error\nmessage: unknown sandbox error")

        out = [
            "status: error",
            f"kind: {error.kind}",
            f"message: {error.message}",
        ]
        if stdout:
            out.extend(["stdout-before-error:", _truncate(stdout, self.max_output_chars)])
        if stderr:
            out.extend(["stderr-before-error:", _truncate(stderr, self.max_output_chars)])
        out.extend(["error-detail:", _truncate(error.formatted, self.max_output_chars)])
        return self._finalize(source, "\n".join(out))


def _build_system_prompt() -> str:
    from ida_codemode_sandbox import IdaSandbox

    return f"{BASE_SYSTEM_PROMPT}\n\n{IdaSandbox.system_prompt()}"


def build_agent(model: Any, evaluator: ScriptEvaluator) -> Any:
    try:
        from pydantic_ai import Agent
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "pydantic-ai is required. Install dependencies for ida-codemode-agent first."
        ) from exc

    agent = Agent(
        model,
        system_prompt=_build_system_prompt(),
        output_type=str,
        defer_model_check=True,
    )

    if hasattr(agent, "tool_plain"):

        # Keep tool callbacks async so pydantic-ai executes them on the event-loop
        # thread instead of offloading sync callables to a worker thread. IDA APIs
        # require main-thread access.
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


def _extract_script_from_tool_args(args: object) -> str | None:
    if isinstance(args, dict):
        args_map = cast(dict[str, Any], args)
        script = args_map.get("script")
        if isinstance(script, str):
            return script
        return json.dumps(args_map, indent=2, ensure_ascii=False)

    if isinstance(args, str):
        try:
            parsed = json.loads(args)
        except json.JSONDecodeError:
            return args

        if isinstance(parsed, dict):
            parsed_map = cast(dict[str, Any], parsed)
            script = parsed_map.get("script")
            if isinstance(script, str):
                return script
            return json.dumps(parsed_map, indent=2, ensure_ascii=False)

        return json.dumps(parsed, indent=2, ensure_ascii=False)

    if args is None:
        return None

    return repr(args)


def _render_tool_call(console: Console, tool_name: str, args: object) -> None:
    script = _extract_script_from_tool_args(args)
    if script is None:
        body: object = Text("(no args)", style="dim")
    else:
        clipped = _truncate(script, 4_000)
        line_count = script.count("\n") + 1
        body = Group(
            Text(f"{line_count} lines • {len(script)} chars", style="dim"),
            Syntax(clipped, "python", line_numbers=True, word_wrap=True),
        )

    console.print(
        Panel(
            body,
            title=f"tool call: {tool_name}",
            border_style="magenta",
        )
    )


_EVAL_RESULT_FIELDS = (
    "status",
    "kind",
    "message",
    "stdout",
    "stderr",
    "result",
    "stdout-before-error",
    "stderr-before-error",
    "error-detail",
)

_EVAL_RESULT_BLOCK_FIELDS = {
    "stdout",
    "stderr",
    "result",
    "stdout-before-error",
    "stderr-before-error",
    "error-detail",
}


def _parse_evaluate_tool_result_text(text: str) -> dict[str, str]:
    """Parse ScriptEvaluator's textual tool result format into keyed fields."""
    parsed: dict[str, str] = {}
    current_block: str | None = None
    block_lines: list[str] = []

    def flush_block() -> None:
        nonlocal current_block, block_lines
        if current_block is None:
            return
        parsed[current_block] = "\n".join(block_lines).rstrip("\n")
        current_block = None
        block_lines = []

    for line in text.splitlines():
        matched_key: str | None = None
        remainder = ""

        for key in _EVAL_RESULT_FIELDS:
            prefix = f"{key}:"
            if line.startswith(prefix):
                matched_key = key
                remainder = line[len(prefix) :].lstrip()
                break

        if matched_key is not None:
            if current_block is not None and (
                matched_key not in _EVAL_RESULT_BLOCK_FIELDS or remainder != ""
            ):
                block_lines.append(line)
                continue

            flush_block()
            if matched_key in _EVAL_RESULT_BLOCK_FIELDS and remainder == "":
                current_block = matched_key
                block_lines = []
            else:
                parsed[matched_key] = remainder
            continue

        if current_block is not None:
            block_lines.append(line)
        else:
            existing = parsed.get("_raw", "")
            parsed["_raw"] = f"{existing}\n{line}".strip("\n")

    flush_block()
    return parsed


def _render_eval_text_block(title: str, text: str, *, border_style: str) -> Panel:
    body = Syntax(_truncate(text or "(empty)", 8_000), "text", line_numbers=False, word_wrap=True)
    return Panel(body, title=title, border_style=border_style)


def _render_eval_result_block(text: str) -> Panel:
    rendered: object
    clipped = _truncate(text or "(empty)", 8_000)

    try:
        rendered = Pretty(ast.literal_eval(clipped), expand_all=False)
    except Exception:
        rendered = Syntax(clipped, "python", line_numbers=False, word_wrap=True)

    return Panel(rendered, title="result", border_style="cyan")


def _render_evaluate_tool_result(console: Console, tool_name: str, text: str) -> bool:
    parsed = _parse_evaluate_tool_result_text(text)
    status = parsed.get("status")
    if status not in {"ok", "error"}:
        return False

    header = Table.grid(expand=True, padding=(0, 1))
    header.add_column(style="bold cyan", no_wrap=True)
    header.add_column(ratio=1)

    status_style = "bold green" if status == "ok" else "bold red"
    header.add_row("status:", Text(status.upper(), style=status_style))

    if kind := parsed.get("kind"):
        header.add_row("kind:", Text(kind, style="yellow"))
    if message := parsed.get("message"):
        header.add_row("message:", Text(message))

    sections: list[RenderableType] = [header]

    stdout = parsed.get("stdout") or parsed.get("stdout-before-error")
    stderr = parsed.get("stderr") or parsed.get("stderr-before-error")
    error_detail = parsed.get("error-detail")

    if stderr and error_detail and stderr.strip() == error_detail.strip():
        # Runtime traces can appear both in stderr and structured error-detail.
        # Prefer a single dedicated error-detail panel.
        stderr = None

    stream_panels: list[Panel] = []
    if stdout:
        stream_panels.append(_render_eval_text_block("stdout", stdout, border_style="green"))
    if stderr:
        stream_panels.append(_render_eval_text_block("stderr", stderr, border_style="red"))

    if len(stream_panels) == 2:
        sections.append(Columns(stream_panels, equal=True, expand=True))
    elif len(stream_panels) == 1:
        sections.append(stream_panels[0])

    if result := parsed.get("result"):
        sections.append(_render_eval_result_block(result))

    if error_detail:
        sections.append(_render_eval_text_block("error detail", error_detail, border_style="red"))

    border_style = "green" if status == "ok" else "red"
    console.print(
        Panel(
            Group(*sections),
            title=f"tool result: {tool_name}",
            border_style=border_style,
        )
    )
    return True


def _render_tool_result(console: Console, tool_name: str, result_content: object) -> None:
    if isinstance(result_content, str) and tool_name == "evaluate_ida_script":
        if _render_evaluate_tool_result(console, tool_name, result_content):
            return

    if isinstance(result_content, str):
        body: object = Syntax(_truncate(result_content, 6_000), "text", line_numbers=False, word_wrap=True)
    else:
        body = Pretty(result_content, expand_all=False)

    console.print(
        Panel(
            body,
            title=f"tool result: {tool_name}",
            border_style="green",
        )
    )


def _serialize_history_for_token_estimate(history: list[Any]) -> str:
    if not history:
        return ""

    looks_like_model_messages = all(
        hasattr(message, "parts") and hasattr(message, "kind") for message in history
    )
    if looks_like_model_messages:
        try:
            from pydantic_ai.messages import ModelMessagesTypeAdapter

            payload = ModelMessagesTypeAdapter.dump_json(history)
            if isinstance(payload, bytes):
                return payload.decode("utf-8", errors="replace")
            return str(payload)
        except Exception:
            pass

    serialized: list[str] = []
    for message in history:
        if hasattr(message, "model_dump_json"):
            try:
                serialized.append(str(message.model_dump_json()))
                continue
            except Exception:
                pass
        if hasattr(message, "model_dump"):
            try:
                serialized.append(
                    json.dumps(message.model_dump(), ensure_ascii=False, default=str)  # type: ignore[call-arg]
                )
                continue
            except Exception:
                pass
        serialized.append(repr(message))

    return "\n".join(serialized)


def _estimate_text_tokens(text: str) -> int:
    if not text:
        return 0

    byte_count = len(text.encode("utf-8", errors="ignore"))
    return max(1, math.ceil(byte_count / 4))


def _estimate_context_tokens(agent: Any, history: list[Any]) -> int:
    system_prompt_parts = getattr(agent, "_system_prompts", ())
    system_prompt_text = "\n".join(
        part if isinstance(part, str) else repr(part) for part in system_prompt_parts
    )

    history_text = _serialize_history_for_token_estimate(history)

    estimate = _estimate_text_tokens(system_prompt_text)
    estimate += _estimate_text_tokens(history_text)

    # Add lightweight overhead for per-message wrappers and tool schemas.
    estimate += 32 + (len(history) * 8)
    return max(estimate, 0)


def _format_compact_token_count(tokens: int) -> str:
    if tokens >= 1_000_000:
        value = tokens / 1_000_000
        suffix = "M"
    elif tokens >= 1_000:
        value = tokens / 1_000
        suffix = "k"
    else:
        return str(tokens)

    compact = f"{value:.1f}".rstrip("0").rstrip(".")
    return f"{compact}{suffix}"


PromptInputKind = Literal["text", "eof", "escape"]


@dataclass(frozen=True)
class PromptInputResult:
    kind: PromptInputKind
    text: str = ""


def _compose_prompt_line(prompt: str, typed: str, right_label: str, width: int) -> str:
    min_spacing = 2
    left = f"{prompt}{typed}"

    if not right_label:
        return left

    line_width = max(width, len(left) + len(right_label) + min_spacing)
    spacing = max(min_spacing, line_width - len(left) - len(right_label))
    return f"{left}{' ' * spacing}{right_label}"


def _consume_escape_sequence(fd: int) -> bool:
    import select

    had_sequence = False
    timeout = 0.03
    while True:
        readable, _, _ = select.select([fd], [], [], timeout)
        if not readable:
            break
        had_sequence = True
        os.read(fd, 1)
        timeout = 0.0

    return had_sequence


def _prompt_user_terminal_input(console: Console, prompt: str, right_label: str) -> PromptInputResult:
    import termios
    import tty

    stdin = sys.stdin
    stream = console.file if hasattr(console.file, "write") else sys.stdout
    fd = stdin.fileno()

    original_settings = termios.tcgetattr(fd)
    decoder = codecs.getincrementaldecoder("utf-8")()
    buffer: list[str] = []

    def redraw() -> None:
        line = _compose_prompt_line(prompt, "".join(buffer), right_label, console.width)
        stream.write("\r")
        stream.write(line)
        stream.write("\x1b[K")
        stream.flush()

    tty.setraw(fd)
    redraw()

    try:
        while True:
            raw = os.read(fd, 1)
            if not raw:
                stream.write("\r\n")
                stream.flush()
                return PromptInputResult(kind="eof")

            decoded = decoder.decode(raw)
            if not decoded:
                continue

            for ch in decoded:
                if ch in ("\r", "\n"):
                    stream.write("\r\n")
                    stream.flush()
                    return PromptInputResult(kind="text", text="".join(buffer).strip())

                if ch == "\x03":
                    buffer.clear()
                    redraw()
                    continue

                if ch == "\x04":
                    if buffer:
                        continue
                    stream.write("\r\n")
                    stream.flush()
                    return PromptInputResult(kind="eof")

                if ch == "\x1b":
                    if _consume_escape_sequence(fd):
                        redraw()
                        continue
                    buffer.clear()
                    redraw()
                    continue

                if ch in ("\x08", "\x7f"):
                    if buffer:
                        buffer.pop()
                        redraw()
                    continue

                if ch.isprintable() or ch == "\t":
                    buffer.append(ch)
                    redraw()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, original_settings)


def _prompt_user_fallback_input(console: Console, prompt: str, right_label: str) -> PromptInputResult:
    left_prompt = Text(prompt, style="bold blue")

    min_spacing = 2
    line_width = max(console.width, len(prompt) + len(right_label) + min_spacing)
    spacing = max(min_spacing, line_width - len(prompt) - len(right_label))

    header = Text.assemble(
        (prompt, "bold blue"),
        (" " * spacing, ""),
        (right_label, "dim"),
    )

    if console.is_terminal:
        console.print(header, end="\r")
    else:
        console.print(header)

    raw_value = console.input(left_prompt)
    if raw_value == "\x1b":
        return PromptInputResult(kind="escape")
    return PromptInputResult(kind="text", text=raw_value.strip())


def _prompt_user_with_context_estimate(
    console: Console, agent: Any, history: list[Any]
) -> PromptInputResult:
    left_prompt_plain = "user › "
    token_estimate = _estimate_context_tokens(agent, history)
    right_label = f"~{_format_compact_token_count(token_estimate)} ctx tokens"

    if console.is_terminal and os.name == "posix" and sys.stdin.isatty() and sys.stdout.isatty():
        return _prompt_user_terminal_input(console, left_prompt_plain, right_label)

    try:
        return _prompt_user_fallback_input(console, left_prompt_plain, right_label)
    except EOFError:
        return PromptInputResult(kind="eof")


class _AgentTurnEscapeInterruptMonitor:
    """Map plain Escape to SIGINT while an agent turn is running."""

    def __init__(self) -> None:
        self.interrupted = False
        self._fd: int | None = None
        self._original_termios: Any = None
        self._stop_event: Any = None
        self._thread: Any = None

    @staticmethod
    def _is_supported() -> bool:
        return os.name == "posix" and sys.stdin.isatty() and sys.stdout.isatty()

    def __enter__(self) -> "_AgentTurnEscapeInterruptMonitor":
        if not self._is_supported():
            return self

        import select
        import signal
        import termios
        import threading
        import tty

        fd = sys.stdin.fileno()
        try:
            original_termios = termios.tcgetattr(fd)
        except Exception:
            return self

        self._fd = fd
        self._original_termios = original_termios
        stop_event = threading.Event()
        self._stop_event = stop_event

        # Cbreak mode gives us immediate key events without full raw-mode behavior.
        tty.setcbreak(fd)

        def monitor() -> None:
            assert self._fd is not None
            while not stop_event.is_set():
                readable, _, _ = select.select([self._fd], [], [], 0.05)
                if not readable:
                    continue

                try:
                    raw = os.read(self._fd, 1)
                except OSError:
                    break

                if not raw:
                    break

                if raw != b"\x1b":
                    continue

                if _consume_escape_sequence(self._fd):
                    # Ignore escape-sequence prefixes (e.g. arrow keys).
                    continue

                self.interrupted = True
                os.kill(os.getpid(), signal.SIGINT)
                break

        thread = threading.Thread(target=monitor, name="agent-turn-escape-interrupt", daemon=True)
        self._thread = thread
        thread.start()
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _tb: Any) -> bool:
        if self._stop_event is not None:
            self._stop_event.set()

        if self._thread is not None:
            self._thread.join(timeout=0.3)

        if self._fd is not None and self._original_termios is not None:
            import termios

            termios.tcsetattr(self._fd, termios.TCSADRAIN, self._original_termios)

        return False


def run_agent_turn(
    *,
    agent: Any,
    user_input: str,
    history: list[Any],
    console: Console,
    session_logger: SessionLogger,
) -> list[Any]:
    from pydantic_ai.messages import (
        FunctionToolCallEvent,
        FunctionToolResultEvent,
        PartDeltaEvent,
        TextPartDelta,
    )
    from rich.live import Live

    stream_text: dict[str, str] = {"value": ""}
    live_ref: dict[str, Live | None] = {"value": None}

    async def event_handler(_ctx: Any, events: Any) -> None:
        async for event in events:
            live = live_ref["value"]
            event_console = live.console if live is not None else console

            if isinstance(event, FunctionToolCallEvent):
                _render_tool_call(event_console, event.part.tool_name, event.part.args)
                continue

            if isinstance(event, FunctionToolResultEvent):
                _render_tool_result(event_console, event.result.tool_name, event.result.content)
                continue

            if isinstance(event, PartDeltaEvent) and isinstance(event.delta, TextPartDelta):
                stream_text["value"] += event.delta.content_delta
                if live is not None:
                    live.update(
                        Panel(
                            Markdown(stream_text["value"] or "_(empty)_"),
                            title="assistant (streaming)",
                            border_style="cyan",
                        )
                    )

    with _AgentTurnEscapeInterruptMonitor():
        with Live(
            Spinner("dots", text="assistant thinking...", style="cyan"),
            console=console,
            refresh_per_second=12,
            transient=True,
        ) as live:
            live_ref["value"] = live
            result = agent.run_sync(
                user_input,
                message_history=history,
                event_stream_handler=event_handler,
            )

    output = str(getattr(result, "output", ""))
    session_logger.log("assistant", content=output)

    console.print(
        Panel(
            Markdown(output if output else "_(empty response)_"),
            title="assistant",
            border_style="cyan",
        )
    )

    if hasattr(result, "all_messages"):
        return result.all_messages()
    return history


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ida-codemode-agent",
        description=(
            "Interactive reverse engineering agent that evaluates Python scripts "
            "inside the Ida code mode sandbox"
        ),
    )
    parser.add_argument(
        "idb_path",
        type=Path,
        nargs="?",
        help="Path to IDA database (.idb/.i64) or input binary to open",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=(
            "Model name (or provider:model). "
            "Default from $IDA_CODEMODE_AGENT_MODEL or google/gemini-3-flash-preview"
        ),
    )
    parser.add_argument(
        "--provider",
        default=DEFAULT_PROVIDER,
        help=(
            "Provider used when --model has no provider prefix. "
            "Default from $IDA_CODEMODE_AGENT_PROVIDER or openrouter"
        ),
    )
    parser.add_argument(
        "--list-models",
        action="store_true",
        help="List known model identifiers (and OpenRouter catalog when reachable) and exit",
    )
    parser.add_argument(
        "--auto-analysis",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable/disable IDA auto analysis (default: enabled)",
    )
    parser.add_argument(
        "--new-database",
        action="store_true",
        help="Create a new database instead of opening an existing one",
    )
    parser.add_argument(
        "--save-on-close",
        action="store_true",
        help="Save DB changes on close (default: auto-save only when creating a new DB)",
    )
    parser.add_argument(
        "--max-script-chars",
        type=int,
        default=20_000,
        help="Maximum script length accepted by the tool",
    )
    parser.add_argument(
        "--max-tool-output-chars",
        type=int,
        default=24_000,
        help="Maximum chars returned from tool output sections",
    )
    parser.add_argument(
        "--prompt",
        "--initial-prompt",
        dest="initial_prompt",
        default=None,
        help="Optional initial prompt to run before entering interactive input",
    )
    return parser.parse_args(argv)


def run_repl(
    agent: Any,
    console: Console,
    session_logger: SessionLogger,
    *,
    initial_prompt: str | None = None,
) -> int:
    history: list[Any] = []
    pending_inputs: list[str] = []
    consecutive_eof_count = 0

    if initial_prompt is not None:
        stripped_initial_prompt = initial_prompt.strip()
        if stripped_initial_prompt:
            pending_inputs.append(stripped_initial_prompt)

    console.print(Rule("ida-codemode-agent"))
    console.print("[bold green]Session ready.[/bold green] Ask reverse engineering questions.")
    console.print(
        "[dim]Commands: /exit, /quit, /clear | Keys: Esc interrupt turn, Ctrl-C clear line, Ctrl-D twice exit[/dim]"
    )

    while True:
        if pending_inputs:
            prompt_result = PromptInputResult(kind="text", text=pending_inputs.pop(0))
        else:
            try:
                prompt_result = _prompt_user_with_context_estimate(console, agent, history)
            except KeyboardInterrupt:
                # In fallback input mode Ctrl-C raises KeyboardInterrupt.
                # Treat it as "clear current input" and continue prompting.
                console.print()
                continue

        if prompt_result.kind == "escape":
            # Escape is reserved for interrupting active agent turns.
            continue

        if prompt_result.kind == "eof":
            consecutive_eof_count += 1
            if consecutive_eof_count >= 2:
                break
            console.print("[dim]Press Ctrl-D again to exit.[/dim]")
            continue

        user_input = prompt_result.text
        consecutive_eof_count = 0

        if not user_input:
            continue

        if user_input in {"/exit", "/quit", "exit", "quit"}:
            break

        if user_input == "/clear":
            history = []
            session_logger.log("history_cleared")
            console.print("[dim]conversation cleared[/dim]")
            continue

        session_logger.log("user", content=user_input)

        try:
            history = run_agent_turn(
                agent=agent,
                user_input=user_input,
                history=history,
                console=console,
                session_logger=session_logger,
            )
        except KeyboardInterrupt:
            session_logger.log("agent_turn_interrupted")
            console.print("[dim]assistant turn interrupted[/dim]")
            continue
        except Exception as exc:  # pragma: no cover
            err = f"model/tool error: {type(exc).__name__}: {exc}"
            session_logger.log("error", stage="agent_turn", message=err)
            console.print(Panel(err, title="error", border_style="red"))

    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    console = Console()
    error_console = Console(stderr=True)

    _configure_logging()

    if args.list_models:
        try:
            models = _available_models()
        except Exception as exc:  # pragma: no cover
            error_console.print(
                f"[red]error:[/red] failed to enumerate models: {type(exc).__name__}: {exc}"
            )
            return 2

        console.print(f"[bold]Available models ({len(models)}):[/bold]")
        for model_name in models:
            console.print(model_name)
        return 0

    if args.idb_path is None:
        error_console.print("[red]error:[/red] missing input path (idb_path)")
        return 2

    model = _resolve_model_name(args.model, args.provider)

    try:
        _validate_model_name(model)
    except Exception as exc:
        error_console.print(f"[red]error:[/red] invalid model '{model}': {type(exc).__name__}: {exc}")
        return 2

    idb_path = args.idb_path

    try:
        plan = resolve_database_plan(idb_path)
    except FileNotFoundError as exc:
        error_console.print(f"[red]error:[/red] {exc}")
        return 2

    try:
        from ida_codemode_sandbox import IdaSandbox
        from ida_domain import Database
        from ida_domain.database import IdaCommandOptions
    except ImportError as exc:  # pragma: no cover
        error_console.print(f"[red]error:[/red] missing runtime dependency: {exc}")
        return 2

    effective_save_on_close = args.save_on_close or plan.creates_database

    ida_options = IdaCommandOptions(
        auto_analysis=args.auto_analysis,
        new_database=args.new_database,
        output_database=plan.output_database,
    )

    session_logger = SessionLogger.create_default()
    session_logger.log(
        "session_start",
        input_path=str(idb_path.expanduser()),
        open_path=str(plan.open_path),
        output_database=plan.output_database,
        creates_database=plan.creates_database,
        model=model,
        auto_analysis=args.auto_analysis,
        new_database=args.new_database,
        save_on_close=effective_save_on_close,
        initial_prompt_provided=bool(args.initial_prompt),
    )

    console.print(f"[bold]Opening IDA:[/bold] {plan.open_path}")
    if plan.creates_database and plan.output_database:
        console.print(f"[yellow]Creating database:[/yellow] {plan.output_database}")
    console.print(f"[bold]Using model:[/bold] {model}")
    console.print(f"[dim]Session log: {session_logger.path}[/dim]")

    try:
        with Database.open(
            str(plan.open_path),
            ida_options,
            save_on_close=effective_save_on_close,
        ) as db:
            sandbox = IdaSandbox(db)
            evaluator = ScriptEvaluator(
                sandbox=sandbox,
                max_script_chars=args.max_script_chars,
                max_output_chars=args.max_tool_output_chars,
                on_evaluation=lambda script, result: session_logger.log(
                    "tool_evaluation",
                    script=script,
                    result=result,
                ),
            )
            agent = build_agent(model, evaluator)
            return run_repl(
                agent,
                console,
                session_logger,
                initial_prompt=args.initial_prompt,
            )
    except Exception as exc:  # pragma: no cover
        session_logger.log("error", stage="startup", message=f"{type(exc).__name__}: {exc}")
        error_console.print(f"[red]error:[/red] failed to start agent: {exc}")
        return 1
    finally:
        session_logger.log("session_end")
        session_logger.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
