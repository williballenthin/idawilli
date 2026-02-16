# ida-codemode-agent: Model Evaluation Framework

## Overview

This document describes the architecture for systematically evaluating LLM
performance on reverse engineering tasks using the ida-codemode-agent. The
framework builds on **pydantic-evals** — Pydantic AI's open-source evaluation
library — and integrates with the existing agent, sandbox, and Logfire
observability stack.

## Goals

1. **Model comparison** — Run the same reverse engineering task against many
   models (Claude, Gemini, GPT, GLM, Qwen, DeepSeek, etc.) via OpenRouter and
   compare success rates, cost, latency, and token usage.
2. **Reasoning effort exploration** — For models that support extended thinking
   / reasoning tokens, vary the reasoning effort level (xhigh, high, medium,
   low, minimal, none) via OpenRouter and measure the effect.
3. **Statistical robustness** — Run each configuration N times (5, 10, 20) and
   aggregate results (mean, stddev, min, max, percentiles).
4. **Prompt A/B testing** — Swap system prompts and measure quantitative
   impact on task success and efficiency.
5. **Longitudinal tracking** — Save evaluation results and compare across time
   (e.g., weekly runs after prompt or tooling changes).
6. **Tool set variation** — Eventually vary the set of exposed tools and
   measure impact.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  eval runner (CLI)                    │
│  `uv run --package ida-codemode-agent python -m     │
│   ida_codemode_agent.eval`                           │
├─────────────────────────────────────────────────────┤
│                                                      │
│  ┌──────────────┐   ┌──────────────────────────┐    │
│  │  EvalConfig  │   │  pydantic-evals Dataset  │    │
│  │  (YAML)      │   │  (cases + evaluators)    │    │
│  │  - models    │   │  - C2 extraction case    │    │
│  │  - runs/model│   │  - future cases          │    │
│  │  - thinking  │   │                          │    │
│  │  - prompts   │   │                          │    │
│  └──────┬───────┘   └────────────┬─────────────┘    │
│         │                        │                   │
│         ▼                        ▼                   │
│  ┌──────────────────────────────────────────────┐   │
│  │          Evaluation Loop                      │   │
│  │  for model in config.models:                  │   │
│  │    for run in range(config.runs_per_model):   │   │
│  │      dataset.evaluate(task_fn(model, ...))    │   │
│  └──────────────────────┬───────────────────────┘   │
│                         │                            │
│                         ▼                            │
│  ┌──────────────────────────────────────────────┐   │
│  │          task function                        │   │
│  │  1. build_agent(model, evaluator)             │   │
│  │  2. agent.run(prompt)                         │   │
│  │  3. return agent output (final message)       │   │
│  │                                               │   │
│  │  Side effects:                                │   │
│  │  - set_eval_attribute("model", ...)           │   │
│  │  - increment_eval_metric("total_tokens", ...) │   │
│  │  - increment_eval_metric("turns", ...)        │   │
│  └──────────────────────┬───────────────────────┘   │
│                         │                            │
│                         ▼                            │
│  ┌──────────────────────────────────────────────┐   │
│  │          Evaluators                           │   │
│  │  - ContainsC2Indicator (bool: magic string)   │   │
│  │  - MaxDuration(seconds=300)                   │   │
│  │  - TokenBudgetEvaluator (score: tokens used)  │   │
│  │  - TurnCountEvaluator (score: turns taken)    │   │
│  │  - CostEvaluator (score: estimated cost)      │   │
│  └──────────────────────┬───────────────────────┘   │
│                         │                            │
│                         ▼                            │
│  ┌──────────────────────────────────────────────┐   │
│  │      EvaluationReport                         │   │
│  │  - per-case: pass/fail, scores, duration      │   │
│  │  - report.print() → rich terminal table       │   │
│  │  - saved to results/ as JSON for comparison   │   │
│  │  - sent to Logfire for dashboard viewing      │   │
│  └──────────────────────────────────────────────┘   │
│                                                      │
└─────────────────────────────────────────────────────┘
         │                              │
         ▼                              ▼
   ┌───────────┐              ┌──────────────────┐
   │  Logfire   │              │  results/*.json  │
   │  Dashboard │              │  (longitudinal)  │
   └───────────┘              └──────────────────┘
```

## Key Design Decisions

### 1. pydantic-evals as the evaluation engine

**Why:** It integrates natively with PydanticAI agents, supports custom
evaluators returning bool/float/str/dict, has built-in Logfire tracing, handles
concurrency and retries, and supports YAML dataset serialization. It is
framework-agnostic — our task function is just an async callable.

**Trade-offs considered:**
- *Roll our own:* More control, but duplicates retry/concurrency/reporting
  logic that pydantic-evals already provides well.
- *pytest-benchmark:* Good for microbenchmarks, not designed for LLM eval
  with non-deterministic outputs and multi-dimensional scoring.
- *External platforms (Braintrust, LangSmith):* Vendor lock-in, and we
  already have Logfire.

### 2. Task function wraps the existing agent

The evaluation task function reuses `build_agent()` and `ScriptEvaluator` from
`cli.py`. This ensures evaluations exercise the exact same code path as
interactive use. The task function:

1. Opens the IDA database (shared across runs for the same binary)
2. Creates a `ScriptEvaluator` with the sandbox
3. Builds the agent with the target model
4. Runs `agent.run(prompt)` (non-interactive, single-shot)
5. Returns the agent's final text output
6. Records token usage, turns, and cost as eval metrics

### 3. Success detection via magic string

The simplest, most reliable evaluator: check whether the agent's final output
contains the known C2 indicator string. This is a deterministic bool evaluator
— no LLM judge needed.

### 4. Model matrix via OpenRouter

All models are accessed through OpenRouter using the `openrouter:vendor/model`
naming convention. This gives us a single API key and unified billing. The eval
config lists model IDs as strings.

### 5. Reasoning effort via OpenRouter

OpenRouter provides a unified `reasoning.effort` parameter that works across
providers (Anthropic, OpenAI, Google, etc.). We use `OpenRouterModelSettings`
with effort levels: `xhigh`, `high`, `medium`, `low`, `minimal`, `none`.
This is cleaner than provider-specific thinking budget integers and works
uniformly across models.

### 6. Cost tracking via OpenRouter inline usage.cost

OpenRouter returns `usage.cost` (real USD including cache discounts) in
every chat completion response. PydanticAI's `OpenRouterModel` parses this
into `ModelResponse.provider_details['cost']`. Since an agentic run may
involve multiple LLM round-trips (tool call loops), we sum the cost from
every `ModelResponse` in the conversation history. No separate API calls
needed — cost data is captured inline with zero additional latency.

### 7. Results persistence for longitudinal comparison

Each evaluation run is saved as a timestamped JSON file in `results/`. A
comparison script can load two result files and diff them. Logfire's built-in
comparison view also supports this when experiments are named consistently.

## File Structure

```
packages/ida-codemode-eval/           # standalone workspace package
├── ida_codemode_eval/
│   ├── cli.py                        # CLI entry point (run, compare, plot)
│   ├── config.py                     # EvalConfig schema (loaded from YAML)
│   ├── evaluators.py                 # custom evaluators (C2 indicator, tokens, cost)
│   ├── runner.py                     # evaluation orchestrator
│   ├── task.py                       # task function (wraps agent)
│   └── compare.py                    # result comparison and plotting
├── evals/
│   └── c2_extraction.yaml            # eval config: C2 config extraction
├── results/                          # saved evaluation results (gitignored)
│   └── .gitkeep
├── tests/
└── pyproject.toml                    # depends on ida-codemode-agent, pydantic-evals
```

## Evaluation Config Schema

```yaml
# evals/eval_config.yaml
name: "c2-extraction-model-comparison"

# IDA database to analyze (path relative to project root or absolute)
database: "tests/data/Practical Malware Analysis Lab 01-01.exe_"

# Number of times to run each model+config combination
runs_per_model: 5

# Maximum time per single agent run (seconds)
timeout_per_run: 300

# Maximum concurrent evaluations (respect API rate limits)
max_concurrency: 2

# Model configurations to evaluate
models:
  - id: "openrouter:anthropic/claude-sonnet-4-20250514"
    label: "claude-sonnet-4"

  - id: "openrouter:anthropic/claude-sonnet-4-20250514"
    label: "claude-sonnet-4-thinking-high"
    reasoning_effort: "high"

  - id: "openrouter:anthropic/claude-sonnet-4-20250514"
    label: "claude-sonnet-4-thinking-low"
    reasoning_effort: "low"

  - id: "openrouter:google/gemini-2.5-pro-preview-05-06"
    label: "gemini-2.5-pro"

  - id: "openrouter:google/gemini-2.5-flash-preview-05-20"
    label: "gemini-2.5-flash"

  - id: "openrouter:openai/gpt-4.1"
    label: "gpt-4.1"

  - id: "openrouter:openai/o4-mini"
    label: "o4-mini"

  - id: "openrouter:deepseek/deepseek-r1"
    label: "deepseek-r1"

  - id: "openrouter:qwen/qwen3-235b-a22b"
    label: "qwen3-235b"

# System prompt override (optional — uses default if omitted)
# system_prompt: "custom prompt here"

# Prompt template sent to the agent
task_prompt: |
  Analyze this binary for command-and-control (C2) indicators.
  The malware contains encoded or hidden C2 configuration data.
  Use the available IDA analysis tools to locate, decode, and extract
  the C2 server address(es) and any related configuration.
  Report all C2 indicators you find.
```

## Dataset Definition

```yaml
# evals/c2_extraction.yaml
cases:
  - name: "c2-config-extraction"
    inputs:
      prompt: |
        Analyze this binary for command-and-control (C2) indicators.
        The malware contains encoded or hidden C2 configuration data.
        Use the available IDA analysis tools to locate, decode, and extract
        the C2 server address(es) and any related configuration.
        Report all C2 indicators you find.
      database: "tests/data/Practical Malware Analysis Lab 01-01.exe_"
    expected_output: null  # we use custom evaluators, not exact match
    metadata:
      magic_string: "PLACEHOLDER_C2_INDICATOR"  # the C2 string to detect
      difficulty: "medium"
      category: "c2-extraction"
```

## Custom Evaluators

### ContainsC2Indicator

```python
@dataclass
class ContainsC2Indicator(Evaluator[EvalInputs, str, EvalMetadata]):
    """Pass if the agent's output contains the expected C2 indicator."""

    case_sensitive: bool = False

    def evaluate(self, ctx: EvaluatorContext[EvalInputs, str, EvalMetadata]) -> bool:
        magic = ctx.metadata.magic_string
        output = ctx.output
        if not self.case_sensitive:
            magic = magic.lower()
            output = output.lower()
        return magic in output
```

### TokenUsageEvaluator

```python
@dataclass
class TokenUsageEvaluator(Evaluator[EvalInputs, str, EvalMetadata]):
    """Report total tokens consumed as a numeric score."""

    def evaluate(self, ctx: EvaluatorContext[EvalInputs, str, EvalMetadata]) -> float:
        return ctx.metrics.get("total_tokens", 0.0)
```

### TurnCountEvaluator

```python
@dataclass
class TurnCountEvaluator(Evaluator[EvalInputs, str, EvalMetadata]):
    """Report number of agent turns as a numeric score."""

    def evaluate(self, ctx: EvaluatorContext[EvalInputs, str, EvalMetadata]) -> float:
        return ctx.metrics.get("turns", 0.0)
```

### CostEvaluator

```python
@dataclass
class CostEvaluator(Evaluator[EvalInputs, str, EvalMetadata]):
    """Report estimated cost in USD as a numeric score."""

    def evaluate(self, ctx: EvaluatorContext[EvalInputs, str, EvalMetadata]) -> float:
        return ctx.metrics.get("cost_usd", 0.0)
```

## Task Function

The task function is the bridge between pydantic-evals and the ida-codemode
agent. It wraps `build_agent()` and runs a single non-interactive session:

```python
async def run_eval_task(inputs: EvalInputs) -> str:
    """Execute a single evaluation run.

    Builds the agent with the specified model, runs the prompt,
    returns the agent's final text output.
    Metrics (tokens, turns, cost, duration) are recorded as eval metrics.
    """
    from pydantic_evals.dataset import set_eval_attribute, increment_eval_metric

    set_eval_attribute("model_id", inputs.model_id)
    set_eval_attribute("model_label", inputs.model_label)
    if inputs.reasoning_effort is not None:
        set_eval_attribute("reasoning_effort", inputs.reasoning_effort)

    # Build model settings with OpenRouterModelSettings for reasoning
    model_settings = _build_model_settings(inputs)

    evaluator = ScriptEvaluator(sandbox=inputs.sandbox)
    agent = build_agent(inputs.model_id, evaluator)

    result = await agent.run(inputs.prompt, model_settings=model_settings)
    output = result.output

    # Record token usage
    usage = result.usage()
    increment_eval_metric("total_tokens", usage.total_tokens or 0)
    increment_eval_metric("input_tokens", usage.input_tokens or 0)
    increment_eval_metric("output_tokens", usage.output_tokens or 0)
    increment_eval_metric("turns", ...)
    increment_eval_metric("tool_calls", ...)

    # Sum real cost from OpenRouter's inline usage.cost field
    # PydanticAI parses this into ModelResponse.provider_details['cost']
    cost_usd = _extract_cost_from_messages(result.all_messages())
    if cost_usd > 0:
        increment_eval_metric("cost_usd", cost_usd)

    return output
```

## Evaluation Runner

The runner orchestrates the full evaluation:

```python
async def run_evaluation(config: EvalConfig) -> None:
    """Run the full evaluation matrix."""
    # Open database once
    db, db_cm = open_database(config.database)
    sandbox = IdaSandbox(db)

    try:
        for model_config in config.models:
            # Build dataset with N repeated cases
            cases = []
            for run_idx in range(config.runs_per_model):
                cases.append(Case(
                    name=f"{model_config.label}-run-{run_idx}",
                    inputs=EvalInputs(
                        prompt=config.task_prompt,
                        model_id=model_config.id,
                        model_label=model_config.label,
                        thinking_budget=model_config.thinking_budget,
                        sandbox=sandbox,
                        database=config.database,
                    ),
                    metadata=EvalMetadata(
                        magic_string=config.magic_string,
                    ),
                ))

            dataset = Dataset(
                cases=cases,
                evaluators=[
                    ContainsC2Indicator(),
                    MaxDuration(seconds=config.timeout_per_run),
                    TokenUsageEvaluator(),
                    TurnCountEvaluator(),
                    CostEvaluator(),
                ],
            )

            report = await dataset.evaluate(
                run_eval_task,
                name=f"c2-extraction/{model_config.label}",
                max_concurrency=config.max_concurrency,
            )
            report.print()

            # Save results
            save_report(report, model_config.label)
    finally:
        db_cm.__exit__(None, None, None)
```

## CLI Entry Point

```bash
# Run full evaluation
ida-codemode-eval run evals/c2_extraction.yaml

# Run single model
ida-codemode-eval run evals/c2_extraction.yaml --model claude-sonnet-4

# Override run count
ida-codemode-eval run evals/c2_extraction.yaml --runs 10

# Compare two saved results
ida-codemode-eval compare results/BEFORE.json results/AFTER.json

# Compare many results in a table
ida-codemode-eval compare-many results/*.json

# Generate comparison plots
ida-codemode-eval plot results/*.json -o comparison.png
```

## Metrics Captured Per Run

| Metric | Type | Source |
|--------|------|--------|
| `success` | bool | ContainsC2Indicator evaluator |
| `duration` | float (seconds) | pydantic-evals built-in |
| `total_tokens` | int | agent usage().total_tokens |
| `input_tokens` | int | agent usage().input_tokens |
| `output_tokens` | int | agent usage().output_tokens |
| `turns` | int | count of response messages |
| `tool_calls` | int | count of tool-call parts in messages |
| `tool_call_failures` | int | count of retry-prompt parts (failed tool calls) |
| `cost_usd` | float | OpenRouter inline `usage.cost` via `ModelResponse.provider_details['cost']` |
| `model_id` | str | eval attribute |
| `model_label` | str | eval attribute |
| `reasoning_effort` | str | eval attribute (xhigh/high/medium/low/minimal/none) |

## Aggregation (Per Model Config)

From N runs of the same model+config:

- **Success rate**: count(success) / N
- **Mean/median duration**: avg, p50, p90
- **Mean tokens**: avg total, request, response
- **Mean turns**: avg tool call rounds
- **Mean cost**: avg estimated USD
- **Consistency**: stddev of success, tokens, duration

## Logfire Integration

The evaluation framework leverages the existing Logfire setup:

1. **Experiment spans** — Each `dataset.evaluate()` creates a top-level
   experiment span visible in Logfire's Evals view.
2. **Per-case spans** — Each case creates a child span with all metrics.
3. **Agent spans** — PydanticAI's built-in instrumentation traces every LLM
   call, tool invocation, and token count inside each case.
4. **Comparison view** — Name experiments consistently
   (`c2-extraction/claude-sonnet-4`) and use Logfire's "Compare selected"
   feature to diff across models or across time.

## Future Extensions

### Prompt Variation
Add `prompts` list to eval config. Each prompt generates its own set of cases:
```yaml
prompts:
  - label: "baseline"
    text: "Analyze this binary for C2 indicators..."
  - label: "chain-of-thought"
    text: "Think step by step. First enumerate functions..."
```

### Tool Set Variation
Add `tool_sets` to eval config. Each set defines which API callbacks are
available in the sandbox:
```yaml
tool_sets:
  - label: "full"
    callbacks: "all"
  - label: "no-decompiler"
    exclude: ["decompile_function_at"]
```

### Multi-Binary Evaluation
Add multiple database entries to test generalization across samples.

### Automated Regression Detection
Compare latest results against a baseline and flag regressions (success rate
drops, cost increases, etc.).
