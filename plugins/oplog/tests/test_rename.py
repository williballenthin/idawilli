import textwrap
from pathlib import Path

from conftest import run_ida_script
from oplog_events import EventList, renamed_event


def test_rename_captures_event(test_binary: Path, temp_idauser: Path, work_dir: Path):
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=temp_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc

            entry = idc.get_inf_attr(idc.INF_START_EA)
            idc.set_name(entry, "test_renamed_entry")
            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())

    renamed_events = [e for e in event_list.root if isinstance(e, renamed_event)]
    assert len(renamed_events) >= 1

    matching = [e for e in renamed_events if e.new_name == "test_renamed_entry"]
    assert len(matching) >= 1

    actual = matching[-1]

    expected = renamed_event(
        event_name="renamed",
        timestamp=actual.timestamp,
        ea=0x401820,
        new_name="test_renamed_entry",
        local_name=False,
        old_name="start",
    )
    assert actual == expected
