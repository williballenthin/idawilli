import textwrap
from pathlib import Path

import pytest

from conftest import run_ida_script
from oplog_events import EventList, UdmModel, lt_udm_changed_event, lt_udm_created_event, lt_udm_deleted_event, lt_udm_renamed_event, lt_udt_expanded_event


def test_lt_udm_created(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that adding a member to a struct triggers lt_udm_created event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_typeinf

            til = ida_typeinf.get_idati()

            udt = ida_typeinf.udt_type_data_t()
            udt.is_union = False

            struct_tif = ida_typeinf.tinfo_t()
            struct_tif.create_udt(udt, ida_typeinf.BTF_STRUCT)

            struct_tif.set_named_type(til, "TestStruct", ida_typeinf.NTF_TYPE)

            struct_tif2 = ida_typeinf.tinfo_t()
            struct_tif2.get_named_type(til, "TestStruct")

            int_tif = ida_typeinf.tinfo_t(ida_typeinf.BT_INT32)

            udm = ida_typeinf.udm_t()
            udm.name = "field_a"
            udm.type = int_tif
            udm.offset = 0
            udm.size = 32

            struct_tif2.add_udm(udm)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    udm_created = [e for e in event_list.root if isinstance(e, lt_udm_created_event)]

    assert len(udm_created) >= 1

    actual = udm_created[-1]

    expected = lt_udm_created_event(
        event_name="lt_udm_created",
        timestamp=actual.timestamp,
        udtname="TestStruct",
        udm=UdmModel(
            offset=0,
            size=32,
            name="field_a",
            cmt="",
            tid=0xffffffffffffffff,
            repr="",
            effalign=0,
            tafld_bits=0,
            fda=0,
        ),
    )
    assert actual == expected


def test_lt_udm_deleted(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that deleting a member from a struct triggers lt_udm_deleted event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_typeinf

            til = ida_typeinf.get_idati()

            udt = ida_typeinf.udt_type_data_t()
            udt.is_union = False

            struct_tif = ida_typeinf.tinfo_t()
            struct_tif.create_udt(udt, ida_typeinf.BTF_STRUCT)
            struct_tif.set_named_type(til, "TestStruct2", ida_typeinf.NTF_TYPE)

            struct_tif2 = ida_typeinf.tinfo_t()
            struct_tif2.get_named_type(til, "TestStruct2")

            int_tif = ida_typeinf.tinfo_t(ida_typeinf.BT_INT32)

            udm = ida_typeinf.udm_t()
            udm.name = "field_a"
            udm.type = int_tif
            udm.offset = 0
            udm.size = 32

            struct_tif2.add_udm(udm)

            struct_tif3 = ida_typeinf.tinfo_t()
            struct_tif3.get_named_type(til, "TestStruct2")

            struct_tif3.del_udm(0)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    udm_deleted = [e for e in event_list.root if isinstance(e, lt_udm_deleted_event)]

    assert len(udm_deleted) >= 1

    actual = udm_deleted[-1]

    assert actual.event_name == "lt_udm_deleted"
    assert actual.udtname == "TestStruct2"
    assert actual.udm.offset == 0
    assert actual.udm.size == 32
    assert actual.udm.name == "field_a"
    assert actual.udm.cmt == ""
    assert actual.udm.tafld_bits == 0
    assert actual.udm.fda == 0


def test_lt_udm_renamed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that renaming a member in a struct triggers lt_udm_renamed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_typeinf

            til = ida_typeinf.get_idati()

            udt = ida_typeinf.udt_type_data_t()
            udt.is_union = False

            struct_tif = ida_typeinf.tinfo_t()
            struct_tif.create_udt(udt, ida_typeinf.BTF_STRUCT)
            struct_tif.set_named_type(til, "TestStruct3", ida_typeinf.NTF_TYPE)

            struct_tif2 = ida_typeinf.tinfo_t()
            struct_tif2.get_named_type(til, "TestStruct3")

            int_tif = ida_typeinf.tinfo_t(ida_typeinf.BT_INT32)

            udm = ida_typeinf.udm_t()
            udm.name = "old_field"
            udm.type = int_tif
            udm.offset = 0
            udm.size = 32

            struct_tif2.add_udm(udm)

            struct_tif3 = ida_typeinf.tinfo_t()
            struct_tif3.get_named_type(til, "TestStruct3")

            struct_tif3.rename_udm(0, "renamed_field")

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    udm_renamed = [e for e in event_list.root if isinstance(e, lt_udm_renamed_event)]

    assert len(udm_renamed) >= 1

    actual = udm_renamed[-1]

    assert actual.event_name == "lt_udm_renamed"
    assert actual.udtname == "TestStruct3"
    assert actual.oldname == "old_field"
    assert actual.udm.name == "renamed_field"


def test_lt_udm_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that modifying a member in a struct triggers lt_udm_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_typeinf

            til = ida_typeinf.get_idati()

            udt = ida_typeinf.udt_type_data_t()
            udt.is_union = False

            struct_tif = ida_typeinf.tinfo_t()
            struct_tif.create_udt(udt, ida_typeinf.BTF_STRUCT)
            struct_tif.set_named_type(til, "TestStruct4", ida_typeinf.NTF_TYPE)

            struct_tif2 = ida_typeinf.tinfo_t()
            struct_tif2.get_named_type(til, "TestStruct4")

            int_tif = ida_typeinf.tinfo_t(ida_typeinf.BT_INT32)

            udm = ida_typeinf.udm_t()
            udm.name = "field_a"
            udm.type = int_tif
            udm.offset = 0
            udm.size = 32

            struct_tif2.add_udm(udm)

            struct_tif3 = ida_typeinf.tinfo_t()
            struct_tif3.get_named_type(til, "TestStruct4")

            char_tif = ida_typeinf.tinfo_t(ida_typeinf.BT_INT8)

            struct_tif3.set_udm_type(0, char_tif)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    udm_changed = [e for e in event_list.root if isinstance(e, lt_udm_changed_event)]

    assert len(udm_changed) >= 1

    actual = udm_changed[-1]

    assert actual.event_name == "lt_udm_changed"
    assert actual.udtname == "TestStruct4"
    assert actual.udmold.name == "field_a"
    assert actual.udmnew.name == "field_a"


def test_lt_udt_expanded(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that expanding a struct with a gap triggers lt_udt_expanded event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_typeinf

            til = ida_typeinf.get_idati()

            udt = ida_typeinf.udt_type_data_t()
            udt.is_union = False

            struct_tif = ida_typeinf.tinfo_t()
            struct_tif.create_udt(udt, ida_typeinf.BTF_STRUCT)
            struct_tif.set_named_type(til, "TestStructExpand", ida_typeinf.NTF_TYPE)

            struct_tif2 = ida_typeinf.tinfo_t()
            struct_tif2.get_named_type(til, "TestStructExpand")

            int_tif = ida_typeinf.tinfo_t(ida_typeinf.BT_INT32)

            udm = ida_typeinf.udm_t()
            udm.name = "field_a"
            udm.type = int_tif
            udm.offset = 0
            udm.size = 32

            struct_tif2.add_udm(udm)

            udm2 = ida_typeinf.udm_t()
            udm2.name = "field_b"
            udm2.type = int_tif
            udm2.offset = 32
            udm2.size = 32

            struct_tif2.add_udm(udm2)

            struct_tif3 = ida_typeinf.tinfo_t()
            struct_tif3.get_named_type(til, "TestStructExpand")

            struct_tif3.expand_udt(1, 4)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    udt_expanded = [e for e in event_list.root if isinstance(e, lt_udt_expanded_event)]

    assert len(udt_expanded) >= 1

    actual = udt_expanded[-1]

    assert actual.event_name == "lt_udt_expanded"
    assert actual.udtname == "TestStructExpand"
    assert actual.delta == 4
