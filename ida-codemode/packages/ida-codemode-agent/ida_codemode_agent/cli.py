#!/usr/bin/env python3
"""CLI for ida-codemode-agent."""

from __future__ import annotations

import argparse
import ast
import json
import logging
import math
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import cache
from pathlib import Path
from typing import Any, Callable, Literal, cast, get_args

import logfire

from rich.console import Console, Group, RenderableType
from rich.markdown import Markdown
from rich.panel import Panel
from rich.pretty import Pretty
from rich.rule import Rule
from rich.spinner import Spinner
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

DEFAULT_MODEL = os.getenv("IDA_CODEMODE_AGENT_MODEL", "openrouter:google/gemini-3-flash-preview")
IDB_EXTENSIONS = {".i64", ".idb"}

THINKING_LEVELS = ("minimal", "low", "medium", "high", "xhigh")

BASE_SYSTEM_PROMPT = """
You are an expert reverse engineering assistant operating on a single opened IDA database.

You have one tool: `evaluate_ida_script`.
Use it to execute sandboxed Python code against the database.

Rules:
- Ground claims in tool output; do not guess.
- A strict static type checker runs before execution; treat typing warnings/errors as blocking and fix them first.
- Scripts run in a sandbox: do not use `import`, `sys`, `os`, `open`, network, or subprocess access.
- Use short, focused scripts; prefer iterative discovery over one giant script.
- Prefer `decompile_function_at(...)` pseudocode over raw disassembly for understanding logic; it is usually more concise and more informative.
- For likely-success API calls, prefer `expect_ok(...)`; `expect_ok(...)` returns `T | None`, so guard every result with `if x is None: ... else: ...` before any `x[...]` or method access.
- Safe template: `r = expect_ok(api_call(...))`; then `if r is None: ... else: use r[...]`.
- For explicit failure branches, use `is_error(payload)` (avoid `"error" in payload` for type narrowing).
- Prefer explicit loops and straightforward control flow; avoid brittle one-liners (`next(...)`, heavy comprehensions, unnecessary `sorted(...)`) unless required.
- If a callback shape is unclear, call `help("callback_name")` first.
- Every script must call at least one IDA callback and print concrete evidence; never send placeholder literals or schema-only lists.
- If a tool run fails with typing errors, send a minimal follow-up script that only fixes the reported type issue.
- In final responses, include concrete evidence (addresses, names, snippets).
""".strip()


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
    models.add(DEFAULT_MODEL)

    try:
        models.update(_openrouter_model_ids())
    except Exception:
        # Network access can fail/offline; keep the static model list available.
        pass

    return sorted(models)


def _parse_openai_compatible_url(model: str) -> tuple[str, str] | None:
    """Parse a URL-based model spec into ``(base_url, model_name)``.

    Returns ``None`` when *model* is not a URL (i.e. a regular
    ``provider:model`` string).

    The model name is separated from the URL by the **last** colon whose
    next character is **not** a digit.  This distinguishes port numbers
    (``http://host:1234/v1``) from model names
    (``http://host:1234/v1:my-model``).

    Examples::

        http://localhost:1234/v1:my-model  -> ("http://localhost:1234/v1", "my-model")
        https://api.example.com/v1:gpt-4o  -> ("https://api.example.com/v1", "gpt-4o")
        http://localhost:1234/v1            -> None  (no model name)
    """
    if not model.startswith(("http://", "https://")):
        return None

    scheme_end = model.index("://") + 3  # position right after "://"
    rest = model[scheme_end:]

    # Walk backwards to find the model-name separator.
    for i in range(len(rest) - 1, -1, -1):
        if rest[i] == ":" and i + 1 < len(rest) and not rest[i + 1].isdigit():
            base_url = model[: scheme_end + i]
            model_name = rest[i + 1 :]
            return base_url, model_name

    return None


def _build_openai_compatible_model(base_url: str, model_name: str) -> Any:
    """Create a pydantic-ai ``OpenAIChatModel`` pointing at *base_url*."""
    from pydantic_ai.models.openai import OpenAIChatModel
    from pydantic_ai.providers.openai import OpenAIProvider

    api_key = os.getenv("OPENAI_API_KEY", "no-key-required")
    provider = OpenAIProvider(base_url=base_url, api_key=api_key)
    return OpenAIChatModel(model_name, provider=provider)


def _is_openai_compatible_url(model: str) -> bool:
    """Return ``True`` when *model* looks like an OpenAI-compatible URL spec."""
    return model.startswith(("http://", "https://"))


def _build_thinking_model_settings(model_ref: str, thinking: str) -> Any:
    """Build provider-appropriate model settings for the given thinking level.

    Maps the unified *thinking* level (one of ``THINKING_LEVELS``) to the
    correct pydantic-ai ``ModelSettings`` subclass based on the provider
    prefix in *model_ref*.

    Returns ``None`` when the provider is unrecognised – the agent will
    simply run without thinking configuration in that case.
    """
    if model_ref.startswith("openrouter:"):
        from pydantic_ai.models.openrouter import OpenRouterModelSettings

        return OpenRouterModelSettings(openrouter_reasoning={"effort": thinking})

    if model_ref.startswith("anthropic:"):
        from pydantic_ai.models.anthropic import AnthropicModelSettings

        _anthropic_effort = {"minimal": "low", "low": "low", "medium": "medium", "high": "high", "xhigh": "max"}
        return AnthropicModelSettings(
            anthropic_thinking={"type": "adaptive"},
            anthropic_effort=_anthropic_effort.get(thinking, "medium"),
        )

    if model_ref.startswith("openai:"):
        from pydantic_ai.models.openai import OpenAIChatModelSettings

        _openai_effort = {"minimal": "low", "low": "low", "medium": "medium", "high": "high", "xhigh": "high"}
        return OpenAIChatModelSettings(openai_reasoning_effort=_openai_effort.get(thinking, "medium"))

    if _is_openai_compatible_url(model_ref):
        from pydantic_ai.models.openai import OpenAIChatModelSettings

        _openai_effort = {"minimal": "low", "low": "low", "medium": "medium", "high": "high", "xhigh": "high"}
        return OpenAIChatModelSettings(openai_reasoning_effort=_openai_effort.get(thinking, "medium"))

    return None


def _validate_model_name(model: str) -> None:
    """Validate that the given provider:model reference can be instantiated."""
    if _is_openai_compatible_url(model):
        parsed = _parse_openai_compatible_url(model)
        if parsed is None:
            raise ValueError(
                f"URL model '{model}' is missing a model name suffix; "
                "append :model-name (for example: http://localhost:1234/v1:my-model)"
            )
        # Light validation: ensure both parts are non-empty.
        base_url, model_name = parsed
        if not base_url or not model_name:
            raise ValueError(
                f"could not parse URL model spec '{model}'; "
                "expected format: http(s)://host[:port][/path]:model-name"
            )
        return

    from pydantic_ai.models import infer_model

    if ":" not in model:
        raise ValueError(
            f"model '{model}' is missing provider prefix; use provider:model "
            "(for example: openrouter:google/gemini-3-flash-preview)"
        )

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


def resolve_database_plan(input_path: Path) -> DatabaseOpenPlan:
    """Resolve an existing IDA database path from user input."""
    path = input_path.expanduser()

    if path.suffix.lower() not in IDB_EXTENSIONS:
        raise FileNotFoundError(
            f"expected an existing IDA database (.i64/.idb), got: {path}"
        )

    if not path.exists():
        raise FileNotFoundError(f"database does not exist: {path}")

    return DatabaseOpenPlan(open_path=path)


@dataclass
class ScriptEvaluator:
    sandbox: Any
    max_output_chars: int = 24_000
    on_evaluation: Callable[[str, str], None] | None = None

    def _finalize(self, source: str, tool_result: str) -> str:
        if self.on_evaluation is not None:
            self.on_evaluation(source, tool_result)
        return tool_result

    def evaluate(self, script: str) -> str:
        with logfire.span(
            "sandbox.evaluate",
            script_length=len(script),
        ) as span:
            source = script.strip()
            if not source:
                span.set_attribute("result_status", "error")
                span.set_attribute("error_kind", "empty")
                return self._finalize(source, "status: error\nmessage: empty script")

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
                tool_result = "\n".join(out)
                span.set_attribute("result_status", "ok")
                span.set_attribute("result_length", len(tool_result))
                return self._finalize(source, tool_result)

            error = result.error
            if error is None:
                span.set_attribute("result_status", "error")
                span.set_attribute("error_kind", "unknown")
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
            tool_result = "\n".join(out)
            span.set_attribute("result_status", "error")
            span.set_attribute("error_kind", error.kind)
            span.set_attribute("result_length", len(tool_result))
            return self._finalize(source, tool_result)


def _build_system_prompt() -> str:
    from ida_codemode_sandbox import IdaSandbox

    return f"{BASE_SYSTEM_PROMPT}\n\n{IdaSandbox.system_prompt()}"


def build_agent(model: Any, evaluator: ScriptEvaluator, model_settings: Any = None) -> Any:
    try:
        from pydantic_ai import Agent
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "pydantic-ai is required. Install dependencies for ida-codemode-agent first."
        ) from exc

    kwargs: dict[str, Any] = dict(
        model=model,
        system_prompt=_build_system_prompt(),
        output_type=str,
        defer_model_check=True,
    )
    if model_settings is not None:
        kwargs["model_settings"] = model_settings

    agent = Agent(**kwargs)

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


def _build_tool_call_body(args: object) -> RenderableType:
    script = _extract_script_from_tool_args(args)
    if script is None:
        return Text("(no args)", style="dim")

    clipped = _truncate(script, 4_000)
    line_count = script.count("\n") + 1
    return Group(
        Text(f"{line_count} lines • {len(script)} chars", style="dim"),
        Syntax(clipped, "python", line_numbers=True, word_wrap=True),
    )


def _render_tool_call(console: Console, tool_name: str, args: object) -> None:
    console.print(
        Panel(
            _build_tool_call_body(args),
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


def _build_eval_text_section(title: str, text: str, *, style: str) -> RenderableType:
    return Group(
        Text(f"{title}:", style=f"bold {style}"),
        Syntax(_truncate(text or "(empty)", 8_000), "text", line_numbers=False, word_wrap=True),
    )


def _build_eval_result_section(text: str) -> RenderableType:
    clipped = _truncate(text or "(empty)", 8_000)

    try:
        rendered: RenderableType = Pretty(ast.literal_eval(clipped), expand_all=False)
    except Exception:
        rendered = Syntax(clipped, "python", line_numbers=False, word_wrap=True)

    return Group(Text("result:", style="bold cyan"), rendered)


def _build_evaluate_tool_result_renderable(text: str) -> tuple[RenderableType, str, str] | None:
    parsed = _parse_evaluate_tool_result_text(text)
    status = parsed.get("status")
    if status not in {"ok", "error"}:
        return None

    meta = Table.grid(expand=True, padding=(0, 1))
    meta.add_column(style="bold cyan", no_wrap=True)
    meta.add_column(ratio=1)

    has_meta = False
    if kind := parsed.get("kind"):
        meta.add_row("kind:", Text(kind, style="yellow"))
        has_meta = True
    if message := parsed.get("message"):
        meta.add_row("message:", Text(message))
        has_meta = True

    sections: list[RenderableType] = []
    if has_meta:
        sections.append(meta)

    stdout = parsed.get("stdout") or parsed.get("stdout-before-error")
    stderr = parsed.get("stderr") or parsed.get("stderr-before-error")
    error_detail = parsed.get("error-detail")

    if stderr and error_detail and stderr.strip() == error_detail.strip():
        # Runtime traces can appear both in stderr and structured error-detail.
        # Prefer a single dedicated error-detail section.
        stderr = None

    result = parsed.get("result")

    only_stdout = bool(stdout) and not has_meta and not stderr and not error_detail and not result
    if only_stdout and stdout is not None:
        sections.append(Syntax(_truncate(stdout, 8_000), "text", line_numbers=False, word_wrap=True))
    else:
        if stdout:
            sections.append(_build_eval_text_section("stdout", stdout, style="green"))
        if stderr:
            sections.append(_build_eval_text_section("stderr", stderr, style="red"))

        if result:
            sections.append(_build_eval_result_section(result))

        if error_detail:
            sections.append(_build_eval_text_section("error detail", error_detail, style="red"))

    if not sections:
        sections.append(Text("(no output)", style="dim"))

    status_label = "OK" if status == "ok" else "ERROR"
    border_style = "green" if status == "ok" else "red"
    return Group(*sections), border_style, f"result: {status_label}"


def _build_tool_result_renderable(tool_name: str, result_content: object) -> tuple[RenderableType, str, str]:
    if isinstance(result_content, str) and tool_name == "evaluate_ida_script":
        parsed = _build_evaluate_tool_result_renderable(result_content)
        if parsed is not None:
            return parsed

    if isinstance(result_content, str):
        body: RenderableType = Syntax(_truncate(result_content, 6_000), "text", line_numbers=False, word_wrap=True)
    else:
        body = Pretty(result_content, expand_all=False)

    return body, "green", "result"


def _render_tool_result(console: Console, tool_name: str, result_content: object) -> None:
    body, border_style, _result_heading = _build_tool_result_renderable(tool_name, result_content)
    console.print(
        Panel(
            body,
            title=f"tool result: {tool_name}",
            border_style=border_style,
        )
    )


def _render_tool_exchange(
    console: Console,
    tool_name: str,
    args: object,
    result_content: object,
) -> None:
    call_body = _build_tool_call_body(args)
    result_body, result_border_style, result_heading = _build_tool_result_renderable(tool_name, result_content)

    console.print(
        Panel(
            Group(
                call_body,
                Rule(result_heading, style="dim"),
                result_body,
            ),
            title=f"tool: {tool_name}",
            border_style=result_border_style,
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


def _estimate_object_tokens(value: object) -> int:
    if value is None:
        return 0

    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, default=str)  # type: ignore[call-arg]
        except Exception:
            text = repr(value)

    return _estimate_text_tokens(text)


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


PromptInputKind = Literal["text", "eof"]


@dataclass(frozen=True)
class PromptInputResult:
    kind: PromptInputKind
    text: str = ""


def _build_left_right_line(
    *,
    left_text: str,
    right_text: str,
    line_width: int,
    left_style: str,
    right_style: str = "dim",
) -> Text:
    min_spacing = 2
    effective_width = max(line_width, len(left_text) + len(right_text) + min_spacing)
    spacing = max(min_spacing, effective_width - len(left_text) - len(right_text))

    return Text.assemble(
        (left_text, left_style),
        (" " * spacing, ""),
        (right_text, right_style),
    )


def _prompt_user_fallback_input(console: Console, prompt: str, right_label: str) -> PromptInputResult:
    left_prompt = Text(prompt, style="bold blue")

    header = _build_left_right_line(
        left_text=prompt,
        right_text=right_label,
        line_width=console.width,
        left_style="bold blue",
    )

    if console.is_terminal:
        console.print(header, end="\r")
    else:
        console.print(header)

    raw_value = console.input(left_prompt)
    return PromptInputResult(kind="text", text=raw_value.strip())


def _prompt_user_with_context_estimate(
    console: Console, agent: Any, history: list[Any]
) -> PromptInputResult:
    left_prompt_plain = "user › "
    token_estimate = _estimate_context_tokens(agent, history)
    right_label = f"~{_format_compact_token_count(token_estimate)} ctx tokens"

    try:
        return _prompt_user_fallback_input(console, left_prompt_plain, right_label)
    except EOFError:
        return PromptInputResult(kind="eof")


def run_agent_turn(
    *,
    agent: Any,
    user_input: str,
    history: list[Any],
    console: Console,
    session_logger: SessionLogger,
    turn_number: int = 0,
) -> list[Any]:
    from pydantic_ai.messages import FunctionToolCallEvent, FunctionToolResultEvent
    from rich.live import Live

    turn_span_cm = logfire.span(
        "agent.turn",
        turn_number=turn_number,
        user_input_length=len(user_input),
    )
    turn_span = turn_span_cm.__enter__()

    live_ref: dict[str, Live | None] = {"value": None}
    pending_tool_calls: dict[str, tuple[str, object]] = {}
    tool_call_count_ref: dict[str, int] = {"value": 0}
    context_estimate_ref: dict[str, int] = {
        "value": _estimate_context_tokens(agent, history) + _estimate_text_tokens(user_input)
    }

    def _build_thinking_spinner() -> Spinner:
        context_label = f"~{_format_compact_token_count(context_estimate_ref['value'])} ctx tokens"
        thinking_line = _build_left_right_line(
            left_text="assistant thinking...",
            right_text=context_label,
            line_width=max(console.width - 2, 0),
            left_style="cyan",
        )
        return Spinner("dots", text=thinking_line, style="cyan")

    def _refresh_thinking_spinner() -> None:
        live = live_ref["value"]
        if live is None:
            return
        live.update(_build_thinking_spinner())

    async def event_handler(_ctx: Any, events: Any) -> None:
        async for event in events:
            live = live_ref["value"]
            event_console = live.console if live is not None else console

            if isinstance(event, FunctionToolCallEvent):
                pending_tool_calls[event.part.tool_call_id] = (event.part.tool_name, event.part.args)
                tool_call_count_ref["value"] += 1
                context_estimate_ref["value"] += _estimate_text_tokens(event.part.tool_name)
                context_estimate_ref["value"] += _estimate_object_tokens(event.part.args)
                _refresh_thinking_spinner()
                continue

            if isinstance(event, FunctionToolResultEvent):
                tool_call_id = getattr(event.result, "tool_call_id", "")
                pending = pending_tool_calls.pop(tool_call_id, None)

                result_tool_name = getattr(event.result, "tool_name", None)
                if isinstance(result_tool_name, str) and result_tool_name:
                    fallback_tool_name = result_tool_name
                elif pending is not None:
                    fallback_tool_name = pending[0]
                else:
                    fallback_tool_name = "tool"

                context_estimate_ref["value"] += _estimate_text_tokens(fallback_tool_name)
                context_estimate_ref["value"] += _estimate_object_tokens(event.result.content)

                if pending is None:
                    _render_tool_result(event_console, fallback_tool_name, event.result.content)
                    _refresh_thinking_spinner()
                    continue

                call_tool_name, call_args = pending
                display_tool_name = call_tool_name or fallback_tool_name
                _render_tool_exchange(
                    event_console,
                    display_tool_name,
                    call_args,
                    event.result.content,
                )
                _refresh_thinking_spinner()
                continue

    try:
        with Live(
            _build_thinking_spinner(),
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
    except BaseException:
        import sys

        turn_span_cm.__exit__(*sys.exc_info())
        raise

    output = str(getattr(result, "output", ""))
    session_logger.log("assistant", content=output)

    turn_span.set_attribute("output_length", len(output))
    turn_span.set_attribute("tool_calls", tool_call_count_ref["value"])
    turn_span_cm.__exit__(None, None, None)

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
        help="Path to an existing IDA database (.idb/.i64)",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=(
            "Model reference in provider:model format "
            "(e.g. openrouter:google/gemini-3-flash-preview) "
            "or an OpenAI-compatible endpoint URL with a model name suffix "
            "(e.g. http://localhost:1234/v1:my-model). "
            "Default from $IDA_CODEMODE_AGENT_MODEL or openrouter:google/gemini-3-flash-preview"
        ),
    )
    parser.add_argument(
        "--list-models",
        action="store_true",
        help="List known model identifiers (and OpenRouter catalog when reachable) and exit",
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
    parser.add_argument(
        "--thinking",
        nargs="?",
        const="medium",
        default=None,
        choices=THINKING_LEVELS,
        metavar="LEVEL",
        help=(
            "Enable model thinking/reasoning. "
            "Levels: minimal, low, medium (default when flag given with no value), high, xhigh. "
            "Omit flag entirely for no thinking."
        ),
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
    turn_counter = 0

    if initial_prompt is not None:
        stripped_initial_prompt = initial_prompt.strip()
        if stripped_initial_prompt:
            pending_inputs.append(stripped_initial_prompt)

    console.print(Rule("ida-codemode-agent"))
    console.print("[bold green]Session ready.[/bold green] Ask reverse engineering questions.")
    console.print("[dim]Commands: /exit, /quit | Ctrl-D twice exit[/dim]")

    while True:
        if pending_inputs:
            prompt_result = PromptInputResult(kind="text", text=pending_inputs.pop(0))
        else:
            prompt_result = _prompt_user_with_context_estimate(console, agent, history)

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

        session_logger.log("user", content=user_input)

        turn_counter += 1
        try:
            history = run_agent_turn(
                agent=agent,
                user_input=user_input,
                history=history,
                console=console,
                session_logger=session_logger,
                turn_number=turn_counter,
            )
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

    model: Any = args.model

    try:
        _validate_model_name(model)
    except Exception as exc:
        error_console.print(f"[red]error:[/red] invalid model '{model}': {type(exc).__name__}: {exc}")
        return 2

    # Build provider-appropriate thinking/reasoning model settings.
    model_settings: Any = None
    if args.thinking is not None:
        model_settings = _build_thinking_model_settings(args.model, args.thinking)

    # Resolve URL-based model specs into a concrete pydantic-ai Model object.
    if _is_openai_compatible_url(model):
        parsed = _parse_openai_compatible_url(model)
        assert parsed is not None  # already validated above
        base_url, model_name = parsed
        model = _build_openai_compatible_model(base_url, model_name)

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

    # --- Logfire observability (no-op when token is absent) ---
    from ida_codemode_agent.observability import configure_observability

    configure_observability(model=model, db_path=str(plan.open_path))

    effective_save_on_close = True

    ida_options = IdaCommandOptions(
        auto_analysis=True,
        new_database=False,
        output_database=None,
    )

    session_logger = SessionLogger.create_default()
    session_logger.log(
        "session_start",
        input_path=str(idb_path.expanduser()),
        open_path=str(plan.open_path),
        model=model,
        thinking=args.thinking,
        auto_analysis=True,
        new_database=False,
        save_on_close=effective_save_on_close,
        initial_prompt_provided=bool(args.initial_prompt),
    )

    console.print(f"[bold]Opening IDA:[/bold] {plan.open_path}")
    console.print(f"[bold]Using model:[/bold] {model}")
    if args.thinking is not None:
        console.print(f"[bold]Thinking:[/bold] {args.thinking}")
    console.print(f"[dim]Session log: {session_logger.path}[/dim]")

    try:
        with logfire.span(
            "session",
            model=model,
            db_path=str(plan.open_path),
            auto_analysis=True,
            initial_prompt_provided=bool(args.initial_prompt),
        ):
            with logfire.span("database.open", db_path=str(plan.open_path)):
                db_cm = Database.open(
                    str(plan.open_path),
                    ida_options,
                    save_on_close=effective_save_on_close,
                )
                db = db_cm.__enter__()

            try:
                sandbox = IdaSandbox(db)
                evaluator = ScriptEvaluator(
                    sandbox=sandbox,
                    max_output_chars=args.max_tool_output_chars,
                    on_evaluation=lambda script, result: session_logger.log(
                        "tool_evaluation",
                        script=script,
                        result=result,
                    ),
                )
                agent = build_agent(model, evaluator, model_settings=model_settings)
                return run_repl(
                    agent,
                    console,
                    session_logger,
                    initial_prompt=args.initial_prompt,
                )
            finally:
                db_cm.__exit__(None, None, None)
    except Exception as exc:  # pragma: no cover
        session_logger.log("error", stage="startup", message=f"{type(exc).__name__}: {exc}")
        error_console.print(f"[red]error:[/red] failed to start agent: {exc}")
        return 1
    finally:
        session_logger.log("session_end")
        session_logger.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
