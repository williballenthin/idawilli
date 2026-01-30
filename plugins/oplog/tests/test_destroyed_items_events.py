import textwrap
from pathlib import Path

import pytest

from conftest import run_ida_script
from oplog_events import EventList, destroyed_items_event


def test_destroyed_items(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that shrinking a segment triggers destroyed_items event.

    The destroyed_items hook only fires through segment operations
    (del_segm, set_segm_start, set_segm_end), not through del_items().
    """
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_segment

            seg = ida_segment.get_first_seg()
            original_end = seg.end_ea
            new_end = original_end - 0x100

            ida_segment.set_segm_end(seg.start_ea, new_end, ida_segment.SEGMOD_KILL)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    destroyed_events = [e for e in event_list.root if isinstance(e, destroyed_items_event)]

    assert len(destroyed_events) >= 1, "No destroyed_items event found"

    actual = destroyed_events[-1]

    expected = destroyed_items_event(
        event_name="destroyed_items",
        timestamp=actual.timestamp,
        ea1=actual.ea1,
        ea2=actual.ea2,
        will_disable_range=True,
    )
    assert actual == expected


def test_destroyed_items_via_segm_start(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test destroying items by moving segment start forward."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_segment

            seg = ida_segment.get_first_seg()
            original_start = seg.start_ea
            new_start = original_start + 0x100

            ida_segment.set_segm_start(seg.start_ea, new_start, ida_segment.SEGMOD_KILL)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    destroyed_events = [e for e in event_list.root if isinstance(e, destroyed_items_event)]

    assert len(destroyed_events) >= 1, "No destroyed_items event found"

    actual = destroyed_events[-1]

    expected = destroyed_items_event(
        event_name="destroyed_items",
        timestamp=actual.timestamp,
        ea1=0x401000,
        ea2=0x401100,
        will_disable_range=True,
    )
    assert actual == expected
