from __future__ import annotations

import ctypes
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts" / "lumina_metadata"))

from lumina_metadata import (  # noqa: E402
    ExtraComment,
    FrameMember,
    FuncHistoriesResult,
    FuncHistoryEntry,
    FunctionMetadata,
    HistoryEntry,
    InstructionComment,
    LuminaRecord,
    QVector,
    get_history_entries,
    get_merged_comment,
    render_function_comment,
)


def make_record(**kwargs) -> LuminaRecord:
    defaults: dict = dict(
        server="primary",
        name="_strrchr",
        size=0x27,
        frequency=23627,
        score=1855,
    )
    defaults.update(kwargs)
    return LuminaRecord(**defaults)


def make_entry(day: int, name: str) -> HistoryEntry:
    return HistoryEntry(
        timestamp=datetime(2021, 5, day, 13, 16, 27, tzinfo=UTC), name=name
    )


def test_render_minimal_record():
    text = render_function_comment([make_record()], local_name="_strrchr")
    assert text.splitlines() == [
        "Lumina primary: _strrchr",
        "  frequency 23,627, score 1855, size 0x27",
    ]


def test_render_full_record():
    record = make_record(
        name="__global_unwind2",
        metadata=FunctionMetadata(
            prototype="void __cdecl __global_unwind2(PVOID TargetFrame)",
            function_comment="Library Function - Single Match\n __global_unwind2\n",
            repeatable_function_comment="unwinds SEH frames",
            instruction_comments=[
                InstructionComment(ea=0x401F4B, text="ReturnValue", repeatable=False),
                InstructionComment(
                    ea=0x401F4D, text="ExceptionRecord", repeatable=True
                ),
            ],
            extra_comments=[
                ExtraComment(
                    ea=0x401F44, anterior="; Exported entry 523.", posterior=""
                )
            ],
            frame_members=[
                FrameMember(offset=0x18, name="TargetFrame", comment=""),
                FrameMember(offset=0x1C, name="", comment="saved"),
            ],
            operand_representation_count=2,
            user_stack_point_count=1,
        ),
    )
    text = render_function_comment([record], local_name="sub_401F44")
    assert text.splitlines() == [
        "Lumina primary: __global_unwind2 (local name: sub_401F44)",
        "  frequency 23,627, score 1855, size 0x27",
        "  type: void __cdecl __global_unwind2(PVOID TargetFrame)",
        "  comment: Library Function - Single Match / __global_unwind2",
        "  repeatable comment: unwinds SEH frames",
        '  frame: TargetFrame, 0x1C "saved"',
        "  2 instruction comments, 1 extra comment, 2 operand representations, 1 user stack point",
    ]


def test_render_truncates_large_records():
    record = make_record(
        name="call_external_umat_",
        size=1,
        metadata=FunctionMetadata(
            prototype="void __fastcall call_external_umat_("
            + ", ".join(f"double *p{i}" for i in range(40))
            + ")",
            frame_members=[
                FrameMember(offset=8 * i, name=f"p{i}", comment="") for i in range(40)
            ],
        ),
    )
    lines = render_function_comment([record], local_name="nullsub_1").splitlines()
    assert lines[2].startswith(
        "  type: void __fastcall call_external_umat_(double *p0, "
    )
    assert lines[2].endswith("...")
    assert len(lines[2]) == len("  type: ") + 200
    assert lines[3] == "  frame: p0, p1, p2, p3, p4, p5, p6, p7, and 32 more"


def test_render_multiple_servers():
    text = render_function_comment(
        [make_record(), make_record(server="secondary", name="strrchr", frequency=3)],
        local_name="_strrchr",
    )
    assert text.splitlines() == [
        "Lumina primary: _strrchr",
        "  frequency 23,627, score 1855, size 0x27",
        "Lumina secondary: strrchr (local name: _strrchr)",
        "  frequency 3, score 1855, size 0x27",
    ]


def test_render_history():
    record = make_record(
        history=[
            make_entry(23, "_strrchr"),
            make_entry(3, "strrchr"),
            make_entry(1, "sub_401550"),
        ]
    )
    text = render_function_comment([record], local_name="_strrchr")
    assert text.splitlines() == [
        "Lumina primary: _strrchr",
        "  frequency 23,627, score 1855, size 0x27",
        "  history: 3 versions, newest first",
        "    2021-05-23 13:16 _strrchr",
        "    2021-05-03 13:16 strrchr",
        "    2021-05-01 13:16 sub_401550",
    ]


def test_render_history_truncates_old_versions():
    record = make_record(history=[make_entry(30 - i, f"name{i}") for i in range(25)])
    lines = render_function_comment([record], local_name="_strrchr").splitlines()
    assert lines[2] == "  history: 25 versions, newest first"
    assert lines[3] == "    2021-05-30 13:16 name0"
    assert lines[12] == "    2021-05-21 13:16 name9"
    assert lines[13] == "    and 15 older versions"
    assert len(lines) == 14


def test_merge_into_empty_comment():
    assert get_merged_comment("", "Lumina primary: foo") == "Lumina primary: foo"


def test_merge_keeps_user_comment():
    merged = get_merged_comment(
        "parses the config\nsee also bar", "Lumina primary: foo"
    )
    assert merged == "parses the config\nsee also bar\n\nLumina primary: foo"


def test_merge_replaces_previous_block():
    first = get_merged_comment("user note", "Lumina primary: foo\n  frequency 1")
    second = get_merged_comment(first, "Lumina primary: bar\n  frequency 2")
    assert second == "user note\n\nLumina primary: bar\n  frequency 2"


def test_merge_removes_block_when_no_records():
    first = get_merged_comment("user note", "Lumina primary: foo")
    assert get_merged_comment(first, "") == "user note"


class NativeResult:
    """
    Builds a GET_FUNC_HISTORIES result in memory with the same layout that libida produces.
    """

    def __init__(self) -> None:
        self.buffers: list[object] = []

    def qvector(self, array: ctypes.Array) -> QVector:
        self.buffers.append(array)
        return QVector(ctypes.addressof(array), len(array), len(array))

    def qstring(self, text: str) -> QVector:
        return self.qvector(ctypes.create_string_buffer(text.encode()))

    def entry(self, secs: int, name: str) -> FuncHistoryEntry:
        return FuncHistoryEntry(
            name=self.qstring(name), metadata=QVector(), ts=secs << 32
        )

    def result(
        self,
        indexes: list[int],
        entries: list[list[FuncHistoryEntry]],
        code: int = 48,
    ) -> FuncHistoriesResult:
        return FuncHistoriesResult(
            code=code,
            pattern_idx_to_entries_idx=self.qvector(
                (ctypes.c_int32 * len(indexes))(*indexes)
            ),
            func_history_entries_vec=self.qvector(
                (QVector * len(entries))(
                    *(self.qvector((FuncHistoryEntry * len(e))(*e)) for e in entries)
                )
            ),
        )


def test_get_history_entries_maps_functions_to_timelines():
    native = NativeResult()
    result = native.result(
        indexes=[1, -1, 0],
        entries=[
            [native.entry(1_600_000_000, "nullsub")],
            [
                native.entry(1_700_000_000, "_strrchr"),
                native.entry(1_500_000_000, "strrchr"),
            ],
        ],
    )

    histories = get_history_entries(result, [0x401000, 0x402000, 0x403000])

    assert list(histories) == [0x401000, 0x403000]
    assert histories[0x401000] == [
        HistoryEntry(
            timestamp=datetime.fromtimestamp(1_700_000_000, UTC),
            name="_strrchr",
        ),
        HistoryEntry(
            timestamp=datetime.fromtimestamp(1_500_000_000, UTC),
            name="strrchr",
        ),
    ]
    assert histories[0x403000][0].name == "nullsub"


def test_get_history_entries_rejects_count_mismatch():
    native = NativeResult()
    result = native.result(indexes=[-1], entries=[])
    with pytest.raises(RuntimeError, match="1 functions in the response for 2"):
        get_history_entries(result, [0x401000, 0x402000])


def test_get_history_entries_rejects_bad_index():
    native = NativeResult()
    result = native.result(indexes=[3], entries=[])
    with pytest.raises(RuntimeError, match="history index 3"):
        get_history_entries(result, [0x401000])


def test_get_history_entries_rejects_wrong_packet():
    native = NativeResult()
    result = native.result(indexes=[], entries=[], code=13)
    with pytest.raises(RuntimeError, match="packet type 13"):
        get_history_entries(result, [])
