import textwrap
from pathlib import Path

import pytest

from conftest import run_ida_script
from oplog_events import EventList, destroyed_items_event


@pytest.mark.xfail(reason="destroyed_items does not fire as expected")
def test_destroyed_items(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that deleting items triggers destroyed_items event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_bytes

            test_ea = 0x401000
            ida_bytes.del_items(test_ea, ida_bytes.DELIT_SIMPLE)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    destroyed_events = [e for e in event_list.root if isinstance(e, destroyed_items_event)]

    matching = [e for e in destroyed_events if e.ea1 == 0x401000]
    assert len(matching) >= 1, "No destroyed_items event found for address 0x401000"

    actual = matching[-1]

    expected = destroyed_items_event(
        event_name="destroyed_items",
        timestamp=actual.timestamp,
        ea1=actual.ea1,
        ea2=actual.ea2,
        will_disable_range=actual.will_disable_range,
    )
    assert actual == expected


@pytest.mark.xfail(reason="destroyed_items does not fire as expected")
def test_destroyed_items_range(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test destroying items in a range."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_bytes

            test_ea = 0x401010
            nbytes = 8
            ida_bytes.del_items(test_ea, ida_bytes.DELIT_SIMPLE, nbytes)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    destroyed_events = [e for e in event_list.root if isinstance(e, destroyed_items_event)]

    matching = [e for e in destroyed_events if e.ea1 == 0x401010]
    assert len(matching) >= 1, "No destroyed_items event found for address 0x401010"

    actual = matching[-1]

    expected = destroyed_items_event(
        event_name="destroyed_items",
        timestamp=actual.timestamp,
        ea1=actual.ea1,
        ea2=actual.ea2,
        will_disable_range=actual.will_disable_range,
    )
    assert actual == expected
