import textwrap
from pathlib import Path

import pytest

from conftest import run_ida_script
from oplog_events import EventList, local_types_changed_event


def test_local_types_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that creating a local type triggers local_types_changed event.

    Uses tinfo_t.set_named_type(None, name) to add a type to the local types library.
    """
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_typeinf

            udt = ida_typeinf.udt_type_data_t()
            udm = udt.add_member("field_a", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32))
            udm = udt.add_member("field_b", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32))

            tif = ida_typeinf.tinfo_t()
            tif.create_udt(udt)
            tif.set_named_type(None, "OplogTestStruct")

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    local_types_events = [e for e in event_list.root if isinstance(e, local_types_changed_event)]

    assert len(local_types_events) >= 1

    matching = [e for e in local_types_events if e.name == "OplogTestStruct"]
    assert len(matching) >= 1, "No local_types_changed event for OplogTestStruct"

    actual = matching[-1]

    assert actual.event_name == "local_types_changed"
    assert actual.ltc == 1  # LTC_ADDED
    assert actual.name == "OplogTestStruct"
    assert actual.ordinal > 0  # ordinal is dynamically assigned
