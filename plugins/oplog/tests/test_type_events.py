import textwrap
from pathlib import Path

import pytest
from conftest import run_ida_script

from oplog_events import (
    EdmModel,
    UdmModel,
    EventList,
    ti_changed_event,
    changing_ti_event,
    op_ti_changed_event,
    changing_op_ti_event,
    lt_edm_changed_event,
    lt_edm_created_event,
    lt_edm_deleted_event,
    lt_edm_renamed_event,
    lt_udm_changed_event,
    lt_udm_created_event,
    lt_udm_deleted_event,
    lt_udm_renamed_event,
    lt_udt_expanded_event,
    local_types_changed_event,
)


def test_ti_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that setting type information triggers changing_ti and ti_changed events."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
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
        """),
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

    changing_expected = changing_ti_event(
        event_name="changing_ti",
        timestamp=changing_actual.timestamp,
        ea=0x90000000,
        new_type=b"=\x04int",
        new_fnames=b"",
        new_type_str="int",
    )
    assert changing_actual == changing_expected

    changed_expected = ti_changed_event(
        event_name="ti_changed",
        timestamp=changed_actual.timestamp,
        ea=0x90000000,
        type=b"=\x04int",
        fnames=b"",
        type_str="int",
    )
    assert changed_actual == changed_expected


@pytest.mark.xfail(reason="set_op_tinfo() is not exposed to Python API")
def test_op_ti_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that setting operand type information triggers changing_op_ti and op_ti_changed events."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_typeinf

            test_ea = 0x401000

            tif = ida_typeinf.tinfo_t()
            tif.get_named_type(None, "int")
            ida_typeinf.set_op_tinfo(test_ea, 0, tif)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
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

    changing_expected = changing_op_ti_event(
        event_name="changing_op_ti",
        timestamp=changing_actual.timestamp,
        ea=0x401000,
        n=0,
        new_type=b"=\x04int",
        new_fnames=b"",
        new_type_str="int",
    )
    assert changing_actual == changing_expected

    changed_expected = op_ti_changed_event(
        event_name="op_ti_changed",
        timestamp=changed_actual.timestamp,
        ea=0x401000,
        n=0,
        type=b"=\x04int",
        fnames=b"",
        type_str="int",
    )
    assert changed_actual == changed_expected


@pytest.mark.xfail(strict=False, reason="may fail on IDA 9.0 due to old behavior")
def test_local_types_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that creating a local type triggers local_types_changed event.

    Uses tinfo_t.set_named_type(None, name) to add a type to the local types library.
    """

    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_typeinf

            udt = ida_typeinf.udt_type_data_t()
            udm = udt.add_member("field_a", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32))
            udm = udt.add_member("field_b", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32))

            tif = ida_typeinf.tinfo_t()
            tif.create_udt(udt)
            tif.set_named_type(None, "OplogTestStruct")

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    local_types_events = [e for e in event_list.root if isinstance(e, local_types_changed_event)]

    assert len(local_types_events) >= 1

    matching = [e for e in local_types_events if e.name == "OplogTestStruct"]
    assert len(matching) >= 1, "No local_types_changed event for OplogTestStruct"

    actual = matching[-1]

    expected = local_types_changed_event(
        event_name="local_types_changed",
        timestamp=actual.timestamp,
        ltc=1,
        name="OplogTestStruct",
        ordinal=15,
    )
    assert actual == expected


@pytest.mark.xfail(strict=False, reason="may fail on IDA 9.0 due to old behavior")
def test_lt_edm_created(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that creating an enum member triggers lt_edm_created event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
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
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    edm_created = [e for e in event_list.root if isinstance(e, lt_edm_created_event)]

    assert len(edm_created) >= 1

    actual = edm_created[-1]

    expected = lt_edm_created_event(
        event_name="lt_edm_created",
        timestamp=actual.timestamp,
        enumname="TestEnum",
        edm=EdmModel(
            name="VALUE_ONE",
            value=1,
            comment="",
        ),
    )
    assert actual == expected


@pytest.mark.xfail(strict=False, reason="may fail on IDA 9.0 due to old behavior")
def test_lt_edm_deleted(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that deleting an enum member triggers lt_edm_deleted event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
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
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    edm_deleted = [e for e in event_list.root if isinstance(e, lt_edm_deleted_event)]

    assert len(edm_deleted) >= 1

    actual = edm_deleted[-1]

    expected = lt_edm_deleted_event(
        event_name="lt_edm_deleted",
        timestamp=actual.timestamp,
        enumname="TestEnum2",
        edm=EdmModel(
            name="VALUE_ONE",
            value=1,
            comment="",
        ),
    )
    assert actual == expected


@pytest.mark.xfail(strict=False, reason="may fail on IDA 9.0 due to old behavior")
def test_lt_edm_renamed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that renaming an enum member triggers lt_edm_renamed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
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
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    edm_renamed = [e for e in event_list.root if isinstance(e, lt_edm_renamed_event)]

    assert len(edm_renamed) >= 1

    actual = edm_renamed[-1]

    expected = lt_edm_renamed_event(
        event_name="lt_edm_renamed",
        timestamp=actual.timestamp,
        enumname="TestEnum3",
        oldname="OLD_VALUE",
        edm=EdmModel(
            name="NEW_VALUE",
            value=1,
            comment="",
        ),
    )
    assert actual == expected


@pytest.mark.xfail(strict=False, reason="may fail on IDA 9.0 due to old behavior")
def test_lt_edm_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that modifying an enum member triggers lt_edm_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
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
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    edm_changed = [e for e in event_list.root if isinstance(e, lt_edm_changed_event)]

    assert len(edm_changed) >= 1

    actual = edm_changed[-1]

    expected = lt_edm_changed_event(
        event_name="lt_edm_changed",
        timestamp=actual.timestamp,
        enumname="TestEnum4",
        edmold=EdmModel(
            name="VALUE_ONE",
            value=1,
            comment="",
        ),
        edmnew=EdmModel(
            name="VALUE_ONE",
            value=999,
            comment="",
        ),
    )
    assert actual == expected


def test_lt_udm_created(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that adding a member to a struct triggers lt_udm_created event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
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
        """),
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
            type_name="(unnamed)",
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
        script=textwrap.dedent(f"""
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
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    udm_deleted = [e for e in event_list.root if isinstance(e, lt_udm_deleted_event)]

    assert len(udm_deleted) >= 1

    actual = udm_deleted[-1]

    expected = lt_udm_deleted_event(
        event_name="lt_udm_deleted",
        timestamp=actual.timestamp,
        udtname="TestStruct2",
        udm=UdmModel(
            offset=0,
            size=32,
            name="field_a",
            cmt="",
            type_name="(unnamed)",
            repr="",
            effalign=4,
            tafld_bits=0,
            fda=0,
        ),
    )
    assert actual == expected


def test_lt_udm_renamed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that renaming a member in a struct triggers lt_udm_renamed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
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
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    udm_renamed = [e for e in event_list.root if isinstance(e, lt_udm_renamed_event)]

    assert len(udm_renamed) >= 1

    actual = udm_renamed[-1]

    expected = lt_udm_renamed_event(
        event_name="lt_udm_renamed",
        timestamp=actual.timestamp,
        udtname="TestStruct3",
        oldname="old_field",
        udm=UdmModel(
            offset=0,
            size=0,
            name="renamed_field",
            cmt="",
            type_name="(unnamed)",
            repr="",
            effalign=0,
            tafld_bits=0,
            fda=0,
        ),
    )
    assert actual == expected


def test_lt_udm_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that modifying a member in a struct triggers lt_udm_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
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
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    udm_changed = [e for e in event_list.root if isinstance(e, lt_udm_changed_event)]

    assert len(udm_changed) >= 1

    actual = udm_changed[-1]

    expected = lt_udm_changed_event(
        event_name="lt_udm_changed",
        timestamp=actual.timestamp,
        udtname="TestStruct4",
        udmold=UdmModel(
            offset=0,
            size=32,
            name="field_a",
            cmt="",
            type_name="(unnamed)",
            repr="",
            effalign=4,
            tafld_bits=0,
            fda=0,
        ),
        udmnew=UdmModel(
            offset=0,
            size=8,
            name="field_a",
            cmt="",
            type_name="(unnamed)",
            repr="",
            effalign=4,
            tafld_bits=0,
            fda=0,
        ),
    )
    assert actual == expected


@pytest.mark.xfail(
    reason="lt_udt_expanded only fires during IDA's struct expansion UI, not via expand_udt() Python API"
)
def test_lt_udt_expanded(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that expanding a struct with a gap triggers lt_udt_expanded event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
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
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    udt_expanded = [e for e in event_list.root if isinstance(e, lt_udt_expanded_event)]

    assert len(udt_expanded) >= 1

    actual = udt_expanded[-1]

    expected = lt_udt_expanded_event(
        event_name="lt_udt_expanded",
        timestamp=actual.timestamp,
        udtname="TestStructExpand",
        udm_name=actual.udm_name,
        delta=4,
    )
    assert actual == expected
