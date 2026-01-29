import textwrap
from pathlib import Path

import pytest

from conftest import run_ida_script
from oplog_events import EventList, changing_ti_event, ti_changed_event


def test_ti_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that setting type information triggers changing_ti and ti_changed events."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_typeinf
            import ida_segment
            import ida_bytes

            # Create a data segment to apply type info (ti hooks need data, not code)
            data_start = 0x90000000
            data_end = 0x90000100
            ida_segment.add_segm(0, data_start, data_end, "DATASEG", "DATA")

            # Make it defined data
            ida_bytes.create_dword(data_start, 4)

            tif = ida_typeinf.tinfo_t()
            tif.get_named_type(None, "int")
            ida_typeinf.apply_tinfo(data_start, tif, ida_typeinf.TINFO_DEFINITE)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    changing_events = [e for e in event_list.root if isinstance(e, changing_ti_event)]
    changed_events = [e for e in event_list.root if isinstance(e, ti_changed_event)]

    # Filter for our specific address
    changing_events = [e for e in changing_events if e.ea == 0x90000000]
    changed_events = [e for e in changed_events if e.ea == 0x90000000]

    assert len(changing_events) >= 1
    assert len(changed_events) >= 1

    changing_actual = changing_events[-1]
    changed_actual = changed_events[-1]

    assert changing_actual.event_name == "changing_ti"
    assert changing_actual.ea == 0x90000000

    assert changed_actual.event_name == "ti_changed"
    assert changed_actual.ea == 0x90000000
