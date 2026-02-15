# ida-codemode-agent

Interactive proof-of-concept reverse engineering agent for IDA Pro.

This package combines:

- [`ida-codemode-sandbox`](../ida-codemode-sandbox) for safe script execution
- [`pydantic-ai`](https://ai.pydantic.dev/) for LLM + tool orchestration
- [`rich`](https://github.com/Textualize/rich) for streaming TUI output, markdown, and tool call visibility

The agent has a **single tool**:

- `evaluate_ida_script(script: str) -> str`

The tool executes Python source in the IDA Code Mode sandbox and returns
captured output and structured errors. Mutation callbacks are available.

## Install

From this directory:

```bash
pip install -e .
```

## Usage

```bash
ida-codemode-agent /path/to/sample.i64
```

Run one initial prompt before interactive mode:

```bash
ida-codemode-agent /path/to/sample.i64 --prompt "Summarize imports and likely capabilities"
```

List known models:

```bash
ida-codemode-agent --list-models
```

Behavior for input paths:

- You must pass an existing `.i64` or `.idb` path.
- The agent does not create new IDA databases.
- Database changes are always saved on close.

## Model defaults

Default model:

- `openrouter:google/gemini-3-flash-preview`

Set credentials, for example:

```bash
export OPENROUTER_API_KEY=...
```

Override with:

```bash
ida-codemode-agent sample.i64 --model anthropic:claude-3-7-sonnet-latest
```

## Session logs

Each chat session is written as JSONL at:

- `$XDG_CACHE_DIR/Hex-Rays/codemode/sessions/*.jsonl`
- fallback: `$XDG_CACHE_HOME/Hex-Rays/codemode/sessions/*.jsonl`
- fallback: `~/.cache/Hex-Rays/codemode/sessions/*.jsonl`

Logs include:

- user prompts
- assistant responses
- executed sandbox scripts
- tool results
- session metadata/errors

## REPL UX

- streaming assistant output
- tool call + tool result panels
- markdown-rendered assistant answers

Commands:

- `/exit`, `/quit`, `exit`, `quit`: leave session

Keyboard controls:

- `Ctrl-D` on an empty line: press once for confirmation, twice to exit

## Thinking / reasoning

By default, the agent does not request model thinking/reasoning tokens.
Use `--thinking` to enable it:

```bash
# xhigh thinking (bare flag)
ida-codemode-agent sample.i64 --thinking

# explicit level
ida-codemode-agent sample.i64 --thinking high
```

Available levels: `minimal`, `low`, `medium`, `high`, `xhigh` (default when flag given).

The flag maps to provider-native settings automatically:

| Provider | Mechanism |
|---|---|
| OpenRouter | `reasoning.effort` (works across all underlying models) |
| Anthropic | adaptive thinking + `effort` |
| OpenAI | `reasoning_effort` |
| OpenAI-compatible URL | `reasoning_effort` |

## CLI options

- positional: `idb_path` (path to an existing IDA `.i64`/`.idb`; not needed with `--list-models`)
- `--list-models` print known model identifiers and exit (includes OpenRouter catalog entries when reachable)
- `--model` model name in `provider:model` format
- `--thinking [LEVEL]` enable model thinking/reasoning (levels: minimal, low, medium, high, xhigh)
- `--prompt` / `--initial-prompt` optional first question to run before interactive prompting
- `--max-tool-output-chars` max returned tool-output size guard
