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
ida-codemode-agent /path/to/sample.exe
```

Run one initial prompt before interactive mode:

```bash
ida-codemode-agent /path/to/sample.exe --prompt "Summarize imports and likely capabilities"
```

List known models:

```bash
ida-codemode-agent --list-models
```

Behavior for input paths:

- If you pass an existing `.i64`/`.idb`, it opens that database.
- If you pass a binary and a companion DB exists (`.i64`/`.idb`), it uses the DB.
- If you pass a binary and no DB exists, it creates `<binary>.i64` automatically.
- If you pass a missing `.i64` but `<base-binary>` exists, it creates that `.i64`.

## Model defaults

Default model/provider:

- provider: `openrouter`
- model: `google/gemini-3-flash-preview`

Equivalent resolved model string:

- `openrouter:google/gemini-3-flash-preview`

Set credentials, for example:

```bash
export OPENROUTER_API_KEY=...
```

Override with:

```bash
ida-codemode-agent sample.i64 --model anthropic:claude-3-7-sonnet-latest
# or
ida-codemode-agent sample.i64 --model gpt-4o-mini --provider openai
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
- `/clear`: clear conversation history

Keyboard controls:

- `Esc`: interrupt an active assistant/tool turn
- `Ctrl-C`: clear the current input line
- `Ctrl-D` on an empty line: press once for confirmation, twice to exit

## CLI options

- positional: `idb_path` (path to IDA database or binary; not needed with `--list-models`)
- `--list-models` print known model identifiers and exit (includes OpenRouter catalog entries when reachable)
- `--model` model name (or `provider:model`)
- `--provider` provider prefix for unqualified `--model`
- `--[no-]auto-analysis` toggle IDA auto analysis (default: on)
- `--new-database` request fresh DB creation
- `--save-on-close` force save on close (newly created DBs are auto-saved)
- `--prompt` / `--initial-prompt` optional first question to run before interactive prompting
- `--max-script-chars` max tool script length guard
- `--max-tool-output-chars` max returned tool-output size guard
