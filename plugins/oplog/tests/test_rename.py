import json
from pathlib import Path

from conftest import run_ida_script


def test_rename_captures_event(test_binary: Path, temp_idauser: Path, work_dir: Path):
    events_path = work_dir / "events.json"

    script = f'''
import idc

entry = idc.get_inf_attr(idc.INF_START_EA)
idc.set_name(entry, "test_renamed_entry")
idc.eval_idc('oplog_export("{events_path}")')
'''

    result = run_ida_script(
        binary_path=test_binary,
        script=script,
        idauser=temp_idauser,
        work_dir=work_dir,
    )

    if result.returncode != 0:
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
        assert False, f"IDA script failed with return code {result.returncode}"

    assert events_path.exists(), f"Events file not created: {events_path}"

    events = json.loads(events_path.read_text())

    renamed_events = [e for e in events if e.get("event_name") == "renamed"]
    assert len(renamed_events) >= 1, f"Expected at least one renamed event, got {len(renamed_events)}"

    matching = [e for e in renamed_events if e.get("new_name") == "test_renamed_entry"]
    assert len(matching) >= 1, f"Expected renamed event with new_name='test_renamed_entry', got: {renamed_events}"
