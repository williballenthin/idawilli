# ida-codemode-eval

Evaluation framework for systematically comparing LLM model performance on
IDA Pro reverse engineering tasks. Built on
[pydantic-evals](https://ai.pydantic.dev/evals/) and integrated with
[Logfire](https://logfire.pydantic.dev/) for observability.

## Quick start

```bash
# From the ida-codemode workspace root
uv sync --all-packages

# Run the C2 extraction evaluation
ida-codemode-eval run evals/c2_extraction.yaml

# Filter to one model
ida-codemode-eval run evals/c2_extraction.yaml --model claude-sonnet-4

# Override number of runs
ida-codemode-eval run evals/c2_extraction.yaml --runs 3

# Compare two saved results
ida-codemode-eval compare results/file_a.json results/file_b.json

# List available models
ida-codemode-eval list-models
```

## What it measures

For each model + configuration combination, across N repeated runs:

| Metric | Description |
|--------|-------------|
| **Success** | Did the agent extract the C2 indicator? (bool) |
| **Duration** | Wall-clock time per run (seconds) |
| **Total tokens** | Combined input + output tokens |
| **Request tokens** | Input/prompt tokens |
| **Response tokens** | Output/completion tokens |
| **Turns** | Number of LLM request/response rounds |
| **Tool calls** | Number of IDA script evaluations |
| **Cost** | Estimated USD (when available) |

Results are aggregated per model: success rate, mean, stddev, min, max.

## Configuration

Evaluations are defined in YAML config files. See `evals/c2_extraction.yaml`
for a complete example.

Key sections:
- `models` — List of model IDs and labels to compare
- `runs_per_model` — Statistical sample size (5, 10, 20)
- `magic_string` — The C2 indicator that determines success
- `task_prompt` — The analysis prompt sent to the agent
- `system_prompt` — Optional override of the default agent system prompt
- `thinking_budget` — Per-model reasoning token budget

## Architecture

See [EVAL_DESIGN.md](EVAL_DESIGN.md) for the full architecture document.

```
ida-codemode-eval/
├── ida_codemode_eval/
│   ├── cli.py          # CLI entry point (run, compare, list-models)
│   ├── config.py       # EvalConfig schema (loaded from YAML)
│   ├── evaluators.py   # Custom evaluators (C2 indicator, token usage, etc.)
│   ├── runner.py       # Evaluation orchestrator
│   └── task.py         # Task function (wraps ida-codemode-agent)
├── evals/              # Evaluation config YAML files
├── results/            # Saved result JSON files (gitignored)
└── tests/
```

## Environment variables

| Variable | Purpose |
|----------|---------|
| `OPENROUTER_API_KEY` | OpenRouter API authentication |
| `LOGFIRE_TOKEN` | Logfire observability (optional) |

## Logfire integration

When `LOGFIRE_TOKEN` is set, every evaluation run produces OpenTelemetry traces
visible in Logfire's Evals dashboard. Experiments are named
`{config.name}/{model_label}` for easy filtering and comparison.
