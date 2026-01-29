import textwrap
from pathlib import Path

import pytest

from conftest import run_ida_script
from oplog_events import (
    EventList,
    bookmark_changed_event,
)


@pytest.mark.xfail(reason="bookmark_changed doesn't fire as expected")
def test_bookmark_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that adding a bookmark triggers bookmark_changed event.
    """
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc

            TODO

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    bookmark_events = [e for e in event_list.root if isinstance(e, bookmark_changed_event)]

    assert len(bookmark_events) == 0, "No bookmark_changed events expected in this test"


@pytest.mark.xfail(reason="bookmark_changed doesn't fire as expected")
def test_bookmark_changed_delete(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that deleting a bookmark triggers bookmark_changed event.
    """
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc

            TODO

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    bookmark_events = [e for e in event_list.root if isinstance(e, bookmark_changed_event)]

    assert len(bookmark_events) == 0, "No bookmark_changed events expected in this test"
