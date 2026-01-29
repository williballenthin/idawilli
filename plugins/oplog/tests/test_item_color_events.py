import textwrap
from pathlib import Path

from conftest import run_ida_script
from oplog_events import (
    EventList,
    item_color_changed_event,
)


def test_item_color_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that setting item color triggers item_color_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc

            test_ea = 0x401000
            idc.set_color(test_ea, idc.CIC_ITEM, 0x0000FF)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    color_events = [e for e in event_list.root if isinstance(e, item_color_changed_event)]

    matching = [e for e in color_events if e.ea == 0x401000]
    assert len(matching) >= 1

    actual = matching[-1]

    expected = item_color_changed_event(
        event_name="item_color_changed",
        timestamp=actual.timestamp,
        ea=0x401000,
        color=255,
    )
    assert actual == expected


def test_item_color_reset(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that resetting item color (DEFCOLOR) triggers item_color_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc

            test_ea = 0x401000
            idc.set_color(test_ea, idc.CIC_ITEM, 0xFF0000)
            idc.set_color(test_ea, idc.CIC_ITEM, idc.DEFCOLOR)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    color_events = [e for e in event_list.root if isinstance(e, item_color_changed_event)]

    matching = [e for e in color_events if e.ea == 0x401000]
    assert len(matching) >= 2

    actual = matching[-1]

    expected = item_color_changed_event(
        event_name="item_color_changed",
        timestamp=actual.timestamp,
        ea=0x401000,
        color=4294967295,
    )
    assert actual == expected
