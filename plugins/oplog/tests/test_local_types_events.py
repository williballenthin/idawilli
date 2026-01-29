import textwrap
from pathlib import Path

import pytest

from conftest import run_ida_script
from oplog_events import EventList, local_types_changed_event


@pytest.mark.xfail(reason="local_types_changed hook does not fire via Python API calls")
def test_local_types_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that creating a local type triggers local_types_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_typeinf

            til = ida_typeinf.get_idati()

            # Try to add a simple type to local type library
            tif = ida_typeinf.tinfo_t()
            if tif.get_named_type(til, "int"):
                til.add_tinfo_type(til.get_last_tid(), "TestType", tif)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    local_types_events = [e for e in event_list.root if isinstance(e, local_types_changed_event)]

    assert len(local_types_events) >= 1

    actual = local_types_events[-1]

    expected = local_types_changed_event(
        event_name="local_types_changed",
        timestamp=actual.timestamp,
        ltc=0,
        ordinal=1,
        name="TestType",
    )
    assert actual == expected
