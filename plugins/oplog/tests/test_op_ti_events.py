import textwrap
from pathlib import Path

import pytest

from conftest import run_ida_script
from oplog_events import EventList, changing_op_ti_event, op_ti_changed_event


@pytest.mark.xfail(reason="set_op_tinfo() is not exposed to Python API")
def test_op_ti_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that setting operand type information triggers changing_op_ti and op_ti_changed events."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_typeinf

            test_ea = 0x401000

            tif = ida_typeinf.tinfo_t()
            tif.get_named_type(None, "int")
            ida_typeinf.set_op_tinfo(test_ea, 0, tif)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    changing_events = [e for e in event_list.root if isinstance(e, changing_op_ti_event)]
    changed_events = [e for e in event_list.root if isinstance(e, op_ti_changed_event)]

    # Filter for our specific address
    changing_events = [e for e in changing_events if e.ea == 0x401000]
    changed_events = [e for e in changed_events if e.ea == 0x401000]

    assert len(changing_events) >= 1
    assert len(changed_events) >= 1

    changing_actual = changing_events[-1]
    changed_actual = changed_events[-1]

    assert changing_actual.event_name == "changing_op_ti"
    assert changing_actual.ea == 0x401000
    assert changing_actual.n == 0

    assert changed_actual.event_name == "op_ti_changed"
    assert changed_actual.ea == 0x401000
    assert changed_actual.n == 0
