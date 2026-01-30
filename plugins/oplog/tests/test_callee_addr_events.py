import textwrap
from pathlib import Path

import pytest

from conftest import run_ida_script
from oplog_events import (
    EventList,
    callee_addr_changed_event,
)


@pytest.mark.xfail(
    reason="callee_addr_changed only fires from UI plugin (Alt+F11), no public Python API exists"
)
def test_callee_addr_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that changing callee address triggers callee_addr_changed event.

    Note: The callee_addr_changed hook is ONLY triggered by the "Change Callee
    Address" UI plugin (Alt+F11) which directly calls gen_idb_event().
    Manipulating xrefs via ida_xref does NOT trigger this hook.
    This test remains xfail because there's no programmatic way to trigger it.
    """
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_xref
            import ida_idaapi

            # Find a CALL instruction in the binary by searching for crefs
            test_ea = None
            callee_ea = None

            for ea in range(0x401000, 0x401100):
                cref = ida_xref.get_first_cref_from(ea)
                if cref != ida_idaapi.BADADDR:
                    test_ea = ea
                    callee_ea = cref
                    break

            if test_ea is not None:
                # Change the callee address by removing and re-adding cref
                old_callee = callee_ea
                ida_xref.del_cref(test_ea, old_callee, False)

                # Add a new reference to a different address
                new_callee = 0x401200
                ida_xref.add_cref(test_ea, new_callee, ida_xref.fl_CN)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    callee_events = [e for e in event_list.root if isinstance(e, callee_addr_changed_event)]

    assert len(callee_events) >= 1

    actual = callee_events[-1]

    assert actual.event_name == "callee_addr_changed"
    assert actual.callee == 0x401200  # new_callee set in the script
    assert 0x401000 <= actual.ea < 0x401100  # ea found in the search range
