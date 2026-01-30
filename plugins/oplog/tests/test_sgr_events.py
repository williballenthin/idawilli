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
        script=textwrap.dedent(f'''
            import idc
            import ida_segment
            import ida_segregs

            seg = ida_segment.get_first_seg()
            R_ds = 3

            ida_segregs.set_default_sreg_value(seg, R_ds, 0x23)
            ida_segregs.split_sreg_range(seg.start_ea + 0x100, R_ds, 0x42, ida_segregs.SR_user, False)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    sgr_events = [e for e in event_list.root if isinstance(e, sgr_changed_event)]

    assert len(sgr_events) >= 1
    actual = sgr_events[-1]

    assert actual.event_name == "sgr_changed"
    assert actual.start_ea == 0x401100  # seg.start_ea + 0x100
    assert actual.regnum == 3  # R_ds
    assert actual.value == 0x42
    assert actual.old_value == 0x23
    assert actual.tag == 2  # SR_user


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
        script=textwrap.dedent(f'''
            import idc
            import ida_segment
            import ida_segregs

            seg = ida_segment.get_first_seg()
            R_ds = 3

            ida_segregs.set_default_sreg_value(seg, R_ds, 0x23)
            ida_segregs.del_sreg_range(seg.start_ea, R_ds)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    sgr_events = [e for e in event_list.root if isinstance(e, sgr_deleted_event)]

    assert len(sgr_events) >= 1
    actual = sgr_events[-1]

    assert actual.event_name == "sgr_deleted"
    assert actual.start_ea == 0x401000  # seg.start_ea
    assert actual.regnum == 3  # R_ds
