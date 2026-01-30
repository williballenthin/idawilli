import textwrap
from pathlib import Path

import pytest

from conftest import run_ida_script
from oplog_events import (
    EdmModel,
    EventList,
    lt_edm_changed_event,
    lt_edm_created_event,
    lt_edm_deleted_event,
    lt_edm_renamed_event,
)


def test_lt_edm_created(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that creating an enum member triggers lt_edm_created event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_typeinf

            til = ida_typeinf.get_idati()

            edt = ida_typeinf.enum_type_data_t()

            enum_tif = ida_typeinf.tinfo_t()
            enum_tif.create_enum(edt)
            enum_tif.set_named_type(til, "TestEnum", ida_typeinf.NTF_TYPE)

            enum_tif2 = ida_typeinf.tinfo_t()
            enum_tif2.get_named_type(til, "TestEnum")

            edm = ida_typeinf.edm_t()
            edm.name = "VALUE_ONE"
            edm.value = 1

            enum_tif2.add_edm(edm)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    edm_created = [e for e in event_list.root if isinstance(e, lt_edm_created_event)]

    assert len(edm_created) >= 1

    actual = edm_created[-1]

    assert actual.event_name == "lt_edm_created"
    assert actual.enumname == "TestEnum"
    assert actual.edm.name == "VALUE_ONE"
    assert actual.edm.value == 1


def test_lt_edm_deleted(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that deleting an enum member triggers lt_edm_deleted event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_typeinf

            til = ida_typeinf.get_idati()

            edt = ida_typeinf.enum_type_data_t()

            enum_tif = ida_typeinf.tinfo_t()
            enum_tif.create_enum(edt)
            enum_tif.set_named_type(til, "TestEnum2", ida_typeinf.NTF_TYPE)

            enum_tif2 = ida_typeinf.tinfo_t()
            enum_tif2.get_named_type(til, "TestEnum2")

            edm = ida_typeinf.edm_t()
            edm.name = "VALUE_ONE"
            edm.value = 1

            enum_tif2.add_edm(edm)

            enum_tif3 = ida_typeinf.tinfo_t()
            enum_tif3.get_named_type(til, "TestEnum2")

            enum_tif3.del_edm(0)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    edm_deleted = [e for e in event_list.root if isinstance(e, lt_edm_deleted_event)]

    assert len(edm_deleted) >= 1

    actual = edm_deleted[-1]

    assert actual.event_name == "lt_edm_deleted"
    assert actual.enumname == "TestEnum2"
    assert actual.edm.name == "VALUE_ONE"
    assert actual.edm.value == 1


def test_lt_edm_renamed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that renaming an enum member triggers lt_edm_renamed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_typeinf

            til = ida_typeinf.get_idati()

            edt = ida_typeinf.enum_type_data_t()

            enum_tif = ida_typeinf.tinfo_t()
            enum_tif.create_enum(edt)
            enum_tif.set_named_type(til, "TestEnum3", ida_typeinf.NTF_TYPE)

            enum_tif2 = ida_typeinf.tinfo_t()
            enum_tif2.get_named_type(til, "TestEnum3")

            edm = ida_typeinf.edm_t()
            edm.name = "OLD_VALUE"
            edm.value = 1

            enum_tif2.add_edm(edm)

            enum_tif3 = ida_typeinf.tinfo_t()
            enum_tif3.get_named_type(til, "TestEnum3")

            enum_tif3.rename_edm(0, "NEW_VALUE")

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    edm_renamed = [e for e in event_list.root if isinstance(e, lt_edm_renamed_event)]

    assert len(edm_renamed) >= 1

    actual = edm_renamed[-1]

    assert actual.event_name == "lt_edm_renamed"
    assert actual.enumname == "TestEnum3"
    assert actual.oldname == "OLD_VALUE"
    assert actual.edm.name == "NEW_VALUE"


def test_lt_edm_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that modifying an enum member triggers lt_edm_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_typeinf

            til = ida_typeinf.get_idati()

            edt = ida_typeinf.enum_type_data_t()

            enum_tif = ida_typeinf.tinfo_t()
            enum_tif.create_enum(edt)
            enum_tif.set_named_type(til, "TestEnum4", ida_typeinf.NTF_TYPE)

            enum_tif2 = ida_typeinf.tinfo_t()
            enum_tif2.get_named_type(til, "TestEnum4")

            edm = ida_typeinf.edm_t()
            edm.name = "VALUE_ONE"
            edm.value = 1

            enum_tif2.add_edm(edm)

            enum_tif3 = ida_typeinf.tinfo_t()
            enum_tif3.get_named_type(til, "TestEnum4")

            enum_tif3.edit_edm(0, 0x3e7)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    edm_changed = [e for e in event_list.root if isinstance(e, lt_edm_changed_event)]

    assert len(edm_changed) >= 1

    actual = edm_changed[-1]

    assert actual.event_name == "lt_edm_changed"
    assert actual.enumname == "TestEnum4"
    assert actual.edmold.name == "VALUE_ONE"
    assert actual.edmold.value == 1
    assert actual.edmnew.name == "VALUE_ONE"
    assert actual.edmnew.value == 0x3e7
