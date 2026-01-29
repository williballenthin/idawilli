import pytest
import textwrap
from pathlib import Path

from conftest import run_ida_script
from oplog_events import (
    EventList,
    sgr_changed_event,
    sgr_deleted_event,
)


@pytest.mark.xfail(
    reason="sgr_changed hook does not fire as expected",
)
def test_sgr_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that changing a segment register triggers sgr_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_segment
            import ida_segregs

            seg = ida_segment.get_first_seg()

            # Split segment register range to trigger sgr_changed
            # Use SR_user tag (2) for user-defined changes
            ida_segregs.split_sreg_range(seg.start_ea, 0, 0x10, ida_segregs.SR_user, False)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    sgr_events = [e for e in event_list.root if isinstance(e, sgr_changed_event)]

    assert len(sgr_events) >= 1
    actual = sgr_events[-1]

    expected = sgr_changed_event(
        event_name="sgr_changed",
        timestamp=actual.timestamp,
        start_ea=0x401000,
        end_ea=0x402000,
        regnum=0,
        value=0x10,
        old_value=0,
        tag=2,
    )
    assert actual == expected


@pytest.mark.xfail(
    reason="sgr_deleted hook does not fire as expected",
)
def test_sgr_deleted(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that deleting a segment register value triggers sgr_deleted event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_segment
            import ida_segregs

            seg = ida_segment.get_first_seg()

            # First set a value
            ida_segregs.split_sreg_range(seg.start_ea, 0, 0x10, ida_segregs.SR_user, False)

            # Now delete it
            ida_segregs.del_sreg_range(seg.start_ea, 0)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    sgr_events = [e for e in event_list.root if isinstance(e, sgr_deleted_event)]

    assert len(sgr_events) >= 1
    actual = sgr_events[-1]

    expected = sgr_deleted_event(
        event_name="sgr_deleted",
        timestamp=actual.timestamp,
        start_ea=0x401000,
        end_ea=0x402000,
        regnum=0,
    )
    assert actual == expected
