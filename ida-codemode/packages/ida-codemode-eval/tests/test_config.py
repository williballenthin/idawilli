"""Tests for evaluation config loading."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from ida_codemode_eval.config import EvalConfig


def test_from_yaml_minimal(tmp_path: Path) -> None:
    config_file = tmp_path / "test.yaml"
    config_file.write_text(dedent("""\
        name: test-eval
        database: sample.i64
        task_prompt: "Analyze this binary."
        magic_string: "evil.com"
        models:
          - id: "openrouter:test/model"
            label: "test-model"
    """))

    config = EvalConfig.from_yaml(config_file)

    assert config.name == "test-eval"
    assert config.database == "sample.i64"
    assert config.magic_string == "evil.com"
    assert len(config.models) == 1
    assert config.models[0].id == "openrouter:test/model"
    assert config.models[0].label == "test-model"
    assert config.models[0].reasoning_effort is None
    assert config.runs_per_model == 5  # default
    assert config.max_concurrency == 1  # default


def test_from_yaml_with_reasoning_effort(tmp_path: Path) -> None:
    config_file = tmp_path / "test.yaml"
    config_file.write_text(dedent("""\
        name: test-eval
        database: sample.i64
        task_prompt: "Analyze this binary."
        magic_string: "evil.com"
        runs_per_model: 10
        models:
          - id: "openrouter:test/model-a"
            label: "model-a"
          - id: "openrouter:test/model-b"
            label: "model-b-thinking"
            reasoning_effort: "high"
          - id: "openrouter:test/model-c"
            label: "model-c-minimal"
            reasoning_effort: "minimal"
    """))

    config = EvalConfig.from_yaml(config_file)

    assert config.runs_per_model == 10
    assert len(config.models) == 3
    assert config.models[0].reasoning_effort is None
    assert config.models[1].reasoning_effort == "high"
    assert config.models[2].reasoning_effort == "minimal"


def test_resolve_database_path_relative(tmp_path: Path) -> None:
    config_file = tmp_path / "test.yaml"
    config_file.write_text(dedent("""\
        name: test
        database: data/sample.i64
        task_prompt: test
        magic_string: test
        models: []
    """))

    config = EvalConfig.from_yaml(config_file)
    resolved = config.resolve_database_path(tmp_path)
    assert resolved == (tmp_path / "data" / "sample.i64").resolve()


def test_resolve_database_path_absolute(tmp_path: Path) -> None:
    config_file = tmp_path / "test.yaml"
    config_file.write_text(dedent(f"""\
        name: test
        database: /absolute/path/sample.i64
        task_prompt: test
        magic_string: test
        models: []
    """))

    config = EvalConfig.from_yaml(config_file)
    resolved = config.resolve_database_path(tmp_path)
    assert resolved == Path("/absolute/path/sample.i64")
