from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import idapro  # noqa: E402, F401

# isort: split
from hint_lumina import (  # noqa: E402
    FunctionMetadata,
    HistoryEntry,
    LuminaRecord,
    is_name_at,
    render_hint,
)

PROTOTYPE_LINE = (
    ".text:00401128 ; int __cdecl main(int argc, const char **argv, const char **envp)"
)
PROC_LINE = (
    ".text:00401128 _main           proc near               ; CODE XREF: start+AF↓p"
)
NAMES = ["_main", "main"]


@pytest.mark.parametrize(
    "line, word",
    [
        (PROC_LINE, "_main"),
        (PROTOTYPE_LINE, "main("),
    ],
)
def test_is_name_at_each_character_of_the_name(line: str, word: str):
    start = line.index(word)
    length = len(word.rstrip("("))
    assert all(is_name_at(line, x, NAMES) for x in range(start, start + length))
    assert not is_name_at(line, start - 1, NAMES)
    assert not is_name_at(line, start + length, NAMES)


@pytest.mark.parametrize(
    "line, word",
    [
        (PROC_LINE, "proc"),
        (PROC_LINE, "start"),
        (PROTOTYPE_LINE, "__cdecl"),
        (PROTOTYPE_LINE, "argc"),
        (".text:00401128 call    main_loop", "main_loop"),
    ],
)
def test_is_name_at_ignores_other_words(line: str, word: str):
    assert not is_name_at(line, line.index(word), NAMES)


def test_is_name_at_matches_demangled_names():
    line = ".text:00401000 ; void __thiscall Foo::bar(Foo *this, int x)"
    assert is_name_at(line, line.index("bar"), ["?bar@Foo@@QAEXH@Z", "Foo::bar"])
    assert not is_name_at(line, line.index("this"), ["?bar@Foo@@QAEXH@Z", "Foo::bar"])


def test_render_hint_without_records():
    assert render_hint([], "_main") == "Lumina: no records for _main"


def test_render_hint_with_history():
    record = LuminaRecord(
        server="primary",
        name="_main",
        size=0x2B4,
        frequency=17,
        score=2060,
        metadata=FunctionMetadata(
            prototype="int __cdecl _main(int argc, const char **argv, const char **envp)"
        ),
        history=[
            HistoryEntry(
                timestamp=datetime(2025, 4, 30, 0, 30, tzinfo=UTC),
                name="_main",
            ),
            HistoryEntry(
                timestamp=datetime(2024, 1, 2, 3, 4, tzinfo=UTC),
                name="sub_401128",
            ),
        ],
    )
    assert render_hint([record], "main_0").splitlines() == [
        "Lumina primary: _main (local name: main_0)",
        "  frequency 17, score 2060, size 0x2B4",
        "  type: int __cdecl _main(int argc, const char **argv, const char **envp)",
        "  history: 2 versions, newest first",
        "    2025-04-30 00:30 _main",
        "    2024-01-02 03:04 sub_401128",
    ]
