import textwrap
from pathlib import Path

import pytest
from conftest import run_ida_script

from oplog_events import (
    EventList,
    SegmentModel,
    SegmMoveInfoModel,
    segm_added_event,
    segm_moved_event,
    adding_segm_event,
    sgr_changed_event,
    sgr_deleted_event,
    segm_deleted_event,
    allsegs_moved_event,
    deleting_segm_event,
    segm_end_changed_event,
    changing_segm_end_event,
    segm_name_changed_event,
    segm_attrs_updated_event,
    segm_class_changed_event,
    segm_start_changed_event,
    changing_segm_start_event,
)


def test_segm_name_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that renaming a segment triggers segm_name_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_segment

            seg = ida_segment.get_first_seg()
            ida_segment.set_segm_name(seg, "renamed_seg")
            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    name_changed = [e for e in event_list.root if isinstance(e, segm_name_changed_event)]
    assert len(name_changed) >= 1

    actual = name_changed[-1]

    expected = segm_name_changed_event(
        event_name="segm_name_changed",
        timestamp=actual.timestamp,
        name="renamed_seg",
        s=SegmentModel(
            start_ea=0x401000,
            end_ea=0x402000,
            name=1,
            sclass=2,
            orgbase=0,
            align=3,
            comb=2,
            perm=5,
            bitness=1,
            flags=16,
            sel=1,
            defsr=[0, 0, 0, 3, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            type=2,
            color=0xFFFFFFFF,
            segment_name="renamed_seg",
            segment_class="CODE",
        ),
    )
    assert actual == expected


def test_segm_class_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that changing a segment class triggers segm_class_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_segment

            seg = ida_segment.get_first_seg()
            ida_segment.set_segm_class(seg, "TEST_CLASS")
            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    class_changed = [e for e in event_list.root if isinstance(e, segm_class_changed_event)]
    assert len(class_changed) >= 1

    actual = class_changed[-1]

    expected = segm_class_changed_event(
        event_name="segm_class_changed",
        timestamp=actual.timestamp,
        sclass="TEST_CLASS",
        s=SegmentModel(
            start_ea=0x401000,
            end_ea=0x402000,
            name=1,
            sclass=2,
            orgbase=0,
            align=3,
            comb=2,
            perm=5,
            bitness=1,
            flags=16,
            sel=1,
            defsr=[0, 0, 0, 3, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            type=2,
            color=0xFFFFFFFF,
            segment_name=".text",
            segment_class="TEST_CLASS",
        ),
    )
    assert actual == expected


def test_segm_attrs_updated(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that changing segment attributes triggers segm_attrs_updated event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_segment

            seg = ida_segment.get_first_seg()
            idc.set_segm_attr(seg.start_ea, idc.SEGATTR_PERM, 7)
            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    attrs_updated = [e for e in event_list.root if isinstance(e, segm_attrs_updated_event)]
    assert len(attrs_updated) >= 1

    actual = attrs_updated[-1]

    expected = segm_attrs_updated_event(
        event_name="segm_attrs_updated",
        timestamp=actual.timestamp,
        s=SegmentModel(
            start_ea=0x401000,
            end_ea=0x402000,
            name=1,
            sclass=2,
            orgbase=0,
            align=3,
            comb=2,
            perm=7,
            bitness=1,
            flags=16,
            sel=1,
            defsr=[0, 0, 0, 3, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            type=2,
            color=0xFFFFFFFF,
            segment_name=".text",
            segment_class="CODE",
        ),
    )
    assert actual == expected


def test_segm_added(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that adding a segment triggers adding_segm and segm_added events."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_segment

            test_seg_name = "TEST_NEW_SEG"
            test_seg_start = 0x90000000
            test_seg_end = 0x90001000

            existing = ida_segment.get_segm_by_name(test_seg_name)
            if existing:
                ida_segment.del_segm(existing.start_ea, ida_segment.SEGMOD_KILL)

            ida_segment.add_segm(0, test_seg_start, test_seg_end, test_seg_name, "DATA")
            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())

    adding_events = [e for e in event_list.root if isinstance(e, adding_segm_event)]
    segm_added_events = [e for e in event_list.root if isinstance(e, segm_added_event)]
    assert len(adding_events) >= 1
    assert len(segm_added_events) >= 1

    matching_adding = [e for e in adding_events if e.s.start_ea == 0x90000000]
    assert len(matching_adding) >= 1

    actual_adding = matching_adding[-1]
    expected_adding = adding_segm_event(
        event_name="adding_segm",
        timestamp=actual_adding.timestamp,
        s=SegmentModel(
            start_ea=0x90000000,
            end_ea=0x90001000,
            name=0,
            sclass=0,
            orgbase=0,
            align=1,
            comb=2,
            perm=0,
            bitness=1,
            flags=0,
            sel=0,
            defsr=[
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
            ],
            type=0,
            color=0xFFFFFFFF,
            segment_name="seg004",
            segment_class=None,
        ),
    )
    assert actual_adding == expected_adding

    matching_added = [e for e in segm_added_events if e.s.segment_name == "TEST_NEW_SEG"]
    assert len(matching_added) >= 1

    actual_added = matching_added[-1]
    expected_added = segm_added_event(
        event_name="segm_added",
        timestamp=actual_added.timestamp,
        s=SegmentModel(
            start_ea=0x90000000,
            end_ea=0x90001000,
            name=7,
            sclass=4,
            orgbase=0,
            align=1,
            comb=2,
            perm=0,
            bitness=1,
            flags=0,
            sel=0,
            defsr=[
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
            ],
            type=3,
            color=0xFFFFFFFF,
            segment_name="TEST_NEW_SEG",
            segment_class="DATA",
        ),
    )
    assert actual_added == expected_added


def test_segm_deleted(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that deleting a segment triggers deleting_segm and segm_deleted events."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_segment

            test_seg_name = "TEST_DEL_SEG"
            test_seg_start = 0x91000000
            test_seg_end = 0x91001000

            existing = ida_segment.get_segm_by_name(test_seg_name)
            if not existing:
                ida_segment.add_segm(0, test_seg_start, test_seg_end, test_seg_name, "DATA")

            seg = ida_segment.get_segm_by_name(test_seg_name)
            seg_start = seg.start_ea
            ida_segment.del_segm(seg_start, ida_segment.SEGMOD_KILL)
            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())

    deleting_events = [e for e in event_list.root if isinstance(e, deleting_segm_event)]
    deleted_events = [e for e in event_list.root if isinstance(e, segm_deleted_event)]
    assert len(deleting_events) >= 1
    assert len(deleted_events) >= 1

    deleting_at_addr = [e for e in deleting_events if e.start_ea == 0x91000000]
    assert len(deleting_at_addr) >= 1

    actual_deleting = deleting_at_addr[-1]
    expected_deleting = deleting_segm_event(
        event_name="deleting_segm",
        timestamp=actual_deleting.timestamp,
        start_ea=0x91000000,
    )
    assert actual_deleting == expected_deleting

    deleted_at_addr = [e for e in deleted_events if e.start_ea == 0x91000000]
    assert len(deleted_at_addr) >= 1

    actual_deleted = deleted_at_addr[-1]
    expected_deleted = segm_deleted_event(
        event_name="segm_deleted",
        timestamp=actual_deleted.timestamp,
        start_ea=0x91000000,
        end_ea=0x91001000,
        flags=1,
    )
    assert actual_deleted == expected_deleted


def test_segm_start_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that changing segment start triggers changing_segm_start and segm_start_changed events."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_segment

            test_seg_name = "TEST_START_SEG"
            test_seg_start = 0x92000000
            test_seg_end = 0x92002000

            existing = ida_segment.get_segm_by_name(test_seg_name)
            if existing:
                ida_segment.del_segm(existing.start_ea, ida_segment.SEGMOD_KILL)

            ida_segment.add_segm(0, test_seg_start, test_seg_end, test_seg_name, "DATA")

            seg = ida_segment.get_segm_by_name(test_seg_name)
            new_start = seg.start_ea + 0x100
            ida_segment.set_segm_start(seg.start_ea, new_start, ida_segment.SEGMOD_KEEP)
            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())

    changing_events = [e for e in event_list.root if isinstance(e, changing_segm_start_event)]
    changed_events = [e for e in event_list.root if isinstance(e, segm_start_changed_event)]
    assert len(changing_events) >= 1
    assert len(changed_events) >= 1

    changing_matching = [e for e in changing_events if e.new_start == 0x92000100]
    assert len(changing_matching) >= 1

    actual_changing = changing_matching[-1]
    expected_changing = changing_segm_start_event(
        event_name="changing_segm_start",
        timestamp=actual_changing.timestamp,
        new_start=0x92000100,
        segmod_flags=2,
        s=SegmentModel(
            start_ea=0x92000000,
            end_ea=0x92002000,
            name=actual_changing.s.name,
            sclass=actual_changing.s.sclass,
            orgbase=0,
            align=1,
            comb=2,
            perm=0,
            bitness=1,
            flags=0,
            sel=0,
            defsr=[
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
            ],
            type=3,
            color=0xFFFFFFFF,
            segment_name="TEST_START_SEG",
            segment_class="DATA",
        ),
    )
    assert actual_changing == expected_changing

    changed_matching = [e for e in changed_events if e.oldstart == 0x92000000]
    assert len(changed_matching) >= 1

    actual_changed = changed_matching[-1]
    expected_changed = segm_start_changed_event(
        event_name="segm_start_changed",
        timestamp=actual_changed.timestamp,
        oldstart=0x92000000,
        s=SegmentModel(
            start_ea=0x92000100,
            end_ea=0x92002000,
            name=actual_changed.s.name,
            sclass=actual_changed.s.sclass,
            orgbase=0,
            align=1,
            comb=2,
            perm=0,
            bitness=1,
            flags=0,
            sel=0,
            defsr=[
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
            ],
            type=3,
            color=0xFFFFFFFF,
            segment_name="TEST_START_SEG",
            segment_class="DATA",
        ),
    )
    assert actual_changed == expected_changed


def test_segm_end_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that changing segment end triggers changing_segm_end and segm_end_changed events."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_segment

            test_seg_name = "TEST_END_SEG"
            test_seg_start = 0x93000000
            test_seg_end = 0x93002000

            existing = ida_segment.get_segm_by_name(test_seg_name)
            if existing:
                ida_segment.del_segm(existing.start_ea, ida_segment.SEGMOD_KILL)

            ida_segment.add_segm(0, test_seg_start, test_seg_end, test_seg_name, "DATA")

            seg = ida_segment.get_segm_by_name(test_seg_name)
            new_end = seg.end_ea - 0x100
            ida_segment.set_segm_end(seg.start_ea, new_end, ida_segment.SEGMOD_KEEP)
            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())

    changing_events = [e for e in event_list.root if isinstance(e, changing_segm_end_event)]
    changed_events = [e for e in event_list.root if isinstance(e, segm_end_changed_event)]
    assert len(changing_events) >= 1
    assert len(changed_events) >= 1

    changing_matching = [e for e in changing_events if e.new_end == 0x93001F00]
    assert len(changing_matching) >= 1

    actual_changing = changing_matching[-1]
    expected_changing = changing_segm_end_event(
        event_name="changing_segm_end",
        timestamp=actual_changing.timestamp,
        new_end=0x93001F00,
        segmod_flags=2,
        s=SegmentModel(
            start_ea=0x93000000,
            end_ea=0x93002000,
            name=actual_changing.s.name,
            sclass=actual_changing.s.sclass,
            orgbase=0,
            align=1,
            comb=2,
            perm=0,
            bitness=1,
            flags=0,
            sel=0,
            defsr=[
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
            ],
            type=3,
            color=0xFFFFFFFF,
            segment_name="TEST_END_SEG",
            segment_class="DATA",
        ),
    )
    assert actual_changing == expected_changing

    changed_matching = [e for e in changed_events if e.oldend == 0x93002000]
    assert len(changed_matching) >= 1

    actual_changed = changed_matching[-1]
    expected_changed = segm_end_changed_event(
        event_name="segm_end_changed",
        timestamp=actual_changed.timestamp,
        oldend=0x93002000,
        s=SegmentModel(
            start_ea=0x93000000,
            end_ea=0x93001F00,
            name=actual_changed.s.name,
            sclass=actual_changed.s.sclass,
            orgbase=0,
            align=1,
            comb=2,
            perm=0,
            bitness=1,
            flags=0,
            sel=0,
            defsr=[
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
            ],
            type=3,
            color=0xFFFFFFFF,
            segment_name="TEST_END_SEG",
            segment_class="DATA",
        ),
    )
    assert actual_changed == expected_changed


def test_segm_moved(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that moving a segment triggers segm_moved event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_segment

            test_seg_name = "TEST_MOVE_SEG"
            test_seg_start = 0x94000000
            test_seg_end = 0x94001000
            new_base = 0x95000000

            existing = ida_segment.get_segm_by_name(test_seg_name)
            if existing:
                ida_segment.del_segm(existing.start_ea, ida_segment.SEGMOD_KILL)

            ida_segment.add_segm(0, test_seg_start, test_seg_end, test_seg_name, "DATA")

            seg = ida_segment.get_segm_by_name(test_seg_name)
            ida_segment.move_segm(seg, new_base)
            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())

    moved_events = [e for e in event_list.root if isinstance(e, segm_moved_event)]
    assert len(moved_events) >= 1

    matching = [e for e in moved_events if e.to == 0x95000000 and e.size == 0x1000]
    assert len(matching) >= 1

    actual = matching[-1]
    expected = segm_moved_event(
        event_name="segm_moved",
        timestamp=actual.timestamp,
        _from=0x94000000,
        to=0x95000000,
        size=0x1000,
        changed_netmap=False,
    )
    assert actual == expected


def test_allsegs_moved(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that rebasing a program triggers allsegs_moved event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_segment

            delta = 0x1000
            ida_segment.rebase_program(delta, ida_segment.MSF_FIXONCE)
            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())

    allsegs_events = [e for e in event_list.root if isinstance(e, allsegs_moved_event)]
    assert len(allsegs_events) >= 1

    actual = allsegs_events[-1]

    expected = allsegs_moved_event(
        event_name="allsegs_moved",
        timestamp=actual.timestamp,
        moves=[
            SegmMoveInfoModel(from_ea=0x403000, to_ea=0x404000, size=0x1000),
            SegmMoveInfoModel(from_ea=0x40206C, to_ea=0x40306C, size=0xF94),
            SegmMoveInfoModel(from_ea=0x402000, to_ea=0x403000, size=0x6C),
            SegmMoveInfoModel(from_ea=0x401000, to_ea=0x402000, size=0x1000),
        ],
    )
    assert actual == expected


@pytest.mark.xfail(
    reason="Segment registers not supported for flat-model 32-bit PE - split_sreg_range returns False",
)
def test_sgr_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that changing a segment register triggers sgr_changed event.

    Note: For flat-model 32-bit PE files, segment register operations are not
    enabled by the x86 processor module. Both set_default_sreg_value() and
    split_sreg_range() return False.
    """
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_segment
            import ida_segregs

            seg = ida_segment.get_first_seg()
            R_ds = 3

            ida_segregs.set_default_sreg_value(seg, R_ds, 0x23)
            ida_segregs.split_sreg_range(seg.start_ea + 0x100, R_ds, 0x42, ida_segregs.SR_user, False)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    sgr_events = [e for e in event_list.root if isinstance(e, sgr_changed_event)]

    assert len(sgr_events) >= 1
    actual = sgr_events[-1]

    expected = sgr_changed_event(
        event_name="sgr_changed",
        timestamp=actual.timestamp,
        start_ea=0x401100,
        regnum=3,
        value=0x42,
        old_value=0x23,
        tag=2,
    )
    assert actual == expected


@pytest.mark.xfail(
    reason="Segment registers not supported for flat-model 32-bit PE - del_sreg_range returns False",
)
def test_sgr_deleted(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that deleting a segment register value triggers sgr_deleted event.

    Note: For flat-model 32-bit PE files, segment register operations are not
    enabled by the x86 processor module.
    """
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_segment
            import ida_segregs

            seg = ida_segment.get_first_seg()
            R_ds = 3

            ida_segregs.set_default_sreg_value(seg, R_ds, 0x23)
            ida_segregs.del_sreg_range(seg.start_ea, R_ds)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    sgr_events = [e for e in event_list.root if isinstance(e, sgr_deleted_event)]

    assert len(sgr_events) >= 1
    actual = sgr_events[-1]

    expected = sgr_deleted_event(
        event_name="sgr_deleted",
        timestamp=actual.timestamp,
        start_ea=0x401000,
        regnum=3,
    )
    assert actual == expected
