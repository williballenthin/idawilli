import textwrap
from pathlib import Path

import pytest

from conftest import run_ida_script
from oplog_events import (
    EventList,
    InsnModel,
    OpModel,
    byte_patched_event,
    changing_op_type_event,
    destroyed_items_event,
    make_code_event,
    make_data_event,
    op_type_changed_event,
)


def test_make_code(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that creating code triggers make_code event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_bytes
            import ida_ua

            test_ea = 0x401000

            ida_bytes.del_items(test_ea, ida_bytes.DELIT_SIMPLE)

            size = ida_ua.create_insn(test_ea)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    make_code_events = [e for e in event_list.root if isinstance(e, make_code_event)]

    matching = [e for e in make_code_events if e.insn.ea == 0x401000]
    assert len(matching) >= 1, "No make_code event found for address 0x401000"

    actual = matching[-1]

    expected = make_code_event(
        event_name="make_code",
        timestamp=actual.timestamp,
        insn=InsnModel(
            cs=0,
            ip=0x401000,
            ea=0x401000,
            itype=0x7a,
            size=4,
            auxpref=0x1c48,
            segpref=0,
            insnpref=0,
            flags=2,
            ops=[
                OpModel(n=0, type=1, offb=0, offo=0, flags=8, dtype=2, reg=2, phrase=2, value=0, addr=0, specval=0, specflag1=0, specflag2=0, specflag3=0, specflag4=0),
                OpModel(n=1, type=4, offb=3, offo=0, flags=8, dtype=2, reg=4, phrase=4, value=0, addr=8, specval=0x1f0000, specflag1=1, specflag2=0x24, specflag3=0, specflag4=0),
                OpModel(n=2, type=0, offb=0, offo=0, flags=8, dtype=0, reg=0, phrase=0, value=0, addr=0, specval=0, specflag1=0, specflag2=0, specflag3=0, specflag4=0),
                OpModel(n=3, type=0, offb=0, offo=0, flags=8, dtype=0, reg=0, phrase=0, value=0, addr=0, specval=0, specflag1=0, specflag2=0, specflag3=0, specflag4=0),
                OpModel(n=4, type=0, offb=0, offo=0, flags=8, dtype=0, reg=0, phrase=0, value=0, addr=0, specval=0, specflag1=0, specflag2=0, specflag3=0, specflag4=0),
                OpModel(n=5, type=0, offb=0, offo=0, flags=8, dtype=0, reg=0, phrase=0, value=0, addr=0, specval=0, specflag1=0, specflag2=0, specflag3=0, specflag4=0),
                OpModel(n=6, type=0, offb=0, offo=0, flags=8, dtype=0, reg=0, phrase=0, value=0, addr=0, specval=0, specflag1=0, specflag2=0, specflag3=0, specflag4=0),
                OpModel(n=7, type=0, offb=0, offo=0, flags=8, dtype=0, reg=0, phrase=0, value=0, addr=0, specval=0, specflag1=0, specflag2=0, specflag3=0, specflag4=0),
            ],
        ),
    )
    assert actual == expected


def test_make_data(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that creating data triggers make_data event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_bytes

            test_ea = 0x401000
            ida_bytes.del_items(test_ea, ida_bytes.DELIT_SIMPLE)
            idc.create_dword(test_ea)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    make_data_events = [e for e in event_list.root if isinstance(e, make_data_event)]

    matching = [e for e in make_data_events if e.ea == 0x401000]
    assert len(matching) >= 1, "No make_data event found for address 0x401000"

    actual = matching[-1]

    expected = make_data_event(
        event_name="make_data",
        timestamp=actual.timestamp,
        ea=0x401000,
        flags=0x20000400,
        tid=0xffffffffffffffff,
        len=4,
    )
    assert actual == expected


def test_make_data_byte(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that creating a byte triggers make_data event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_bytes

            test_ea = 0x401010
            ida_bytes.del_items(test_ea, ida_bytes.DELIT_SIMPLE)
            idc.create_byte(test_ea)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    make_data_events = [e for e in event_list.root if isinstance(e, make_data_event)]

    matching = [e for e in make_data_events if e.ea == 0x401010]
    assert len(matching) >= 1, "No make_data event found for address 0x401010"

    actual = matching[-1]

    expected = make_data_event(
        event_name="make_data",
        timestamp=actual.timestamp,
        ea=0x401010,
        flags=0x400,
        tid=0xffffffffffffffff,
        len=1,
    )
    assert actual == expected


def test_make_data_word(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that creating a word triggers make_data event.

    Uses DELIT_EXPAND to properly clear byte tails that may exist
    at the target address before creating word data.
    """
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_bytes
            import ida_segment

            seg = ida_segment.get_first_seg()
            test_ea = seg.start_ea + 0x60

            ida_bytes.del_items(test_ea, ida_bytes.DELIT_EXPAND, 2)
            idc.create_word(test_ea)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    make_data_events = [e for e in event_list.root if isinstance(e, make_data_event)]

    test_ea = 0x401060
    matching = [e for e in make_data_events if e.ea == test_ea]
    assert len(matching) >= 1, f"No make_data event found for address {hex(test_ea)}"

    actual = matching[-1]

    expected = make_data_event(
        event_name="make_data",
        timestamp=actual.timestamp,
        ea=test_ea,
        flags=0x10000400,
        tid=0xffffffffffffffff,
        len=2,
    )
    assert actual == expected


def test_byte_patched(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that patching a byte triggers byte_patched event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_bytes

            test_ea = 0x401000
            ida_bytes.patch_byte(test_ea, 0x90)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    patched_events = [e for e in event_list.root if isinstance(e, byte_patched_event)]

    matching = [e for e in patched_events if e.ea == 0x401000]
    assert len(matching) >= 1, "No byte_patched event found for address 0x401000"

    actual = matching[-1]

    expected = byte_patched_event(
        event_name="byte_patched",
        timestamp=actual.timestamp,
        ea=0x401000,
        old_value=0x8b,
    )
    assert actual == expected


def test_byte_patched_multiple(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that patching multiple bytes triggers multiple byte_patched events."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_bytes

            test_ea = 0x401000
            ida_bytes.patch_byte(test_ea, 0x90)
            ida_bytes.patch_byte(test_ea + 1, 0x90)
            ida_bytes.patch_byte(test_ea + 2, 0x90)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    patched_events = [e for e in event_list.root if isinstance(e, byte_patched_event)]

    matching_base = [e for e in patched_events if e.ea == 0x401000]
    matching_plus1 = [e for e in patched_events if e.ea == 0x401001]
    matching_plus2 = [e for e in patched_events if e.ea == 0x401002]

    assert len(matching_base) >= 1, "No byte_patched event found for address 0x401000"
    assert len(matching_plus1) >= 1, "No byte_patched event found for address 0x401001"
    assert len(matching_plus2) >= 1, "No byte_patched event found for address 0x401002"

    expected_1 = byte_patched_event(
        event_name="byte_patched",
        timestamp=matching_base[-1].timestamp,
        ea=0x401000,
        old_value=0x8b,
    )
    assert matching_base[-1] == expected_1

    expected_2 = byte_patched_event(
        event_name="byte_patched",
        timestamp=matching_plus1[-1].timestamp,
        ea=0x401001,
        old_value=0x54,
    )
    assert matching_plus1[-1] == expected_2

    expected_3 = byte_patched_event(
        event_name="byte_patched",
        timestamp=matching_plus2[-1].timestamp,
        ea=0x401002,
        old_value=0x24,
    )
    assert matching_plus2[-1] == expected_3


def test_byte_patched_word(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that patching a word (2 bytes) generates multiple byte_patched events."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_bytes

            test_ea = 0x401010
            ida_bytes.patch_word(test_ea, 0x9090)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    patched_events = [e for e in event_list.root if isinstance(e, byte_patched_event)]

    matching = [e for e in patched_events if e.ea in (0x401010, 0x401011)]
    assert len(matching) >= 2, "Expected at least 2 byte_patched events for word patch"


def test_destroyed_items(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that shrinking a segment triggers destroyed_items event.

    The destroyed_items hook only fires through segment operations
    (del_segm, set_segm_start, set_segm_end), not through del_items().
    """
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_segment

            seg = ida_segment.get_first_seg()
            original_end = seg.end_ea
            new_end = original_end - 0x100

            ida_segment.set_segm_end(seg.start_ea, new_end, ida_segment.SEGMOD_KILL)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    destroyed_events = [e for e in event_list.root if isinstance(e, destroyed_items_event)]

    assert len(destroyed_events) >= 1, "No destroyed_items event found"

    actual = destroyed_events[-1]

    expected = destroyed_items_event(
        event_name="destroyed_items",
        timestamp=actual.timestamp,
        ea1=actual.ea1,
        ea2=actual.ea2,
        will_disable_range=True,
    )
    assert actual == expected


def test_destroyed_items_via_segm_start(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test destroying items by moving segment start forward."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_segment

            seg = ida_segment.get_first_seg()
            original_start = seg.start_ea
            new_start = original_start + 0x100

            ida_segment.set_segm_start(seg.start_ea, new_start, ida_segment.SEGMOD_KILL)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    destroyed_events = [e for e in event_list.root if isinstance(e, destroyed_items_event)]

    assert len(destroyed_events) >= 1, "No destroyed_items event found"

    actual = destroyed_events[-1]

    expected = destroyed_items_event(
        event_name="destroyed_items",
        timestamp=actual.timestamp,
        ea1=0x401000,
        ea2=0x401100,
        will_disable_range=True,
    )
    assert actual == expected


def test_op_type_changed_hex(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that changing operand type to hex triggers op_type events."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc

            test_ea = 0x401000
            idc.op_hex(test_ea, 1)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    changing_events = [e for e in event_list.root if isinstance(e, changing_op_type_event)]
    changed_events = [e for e in event_list.root if isinstance(e, op_type_changed_event)]

    assert len(changing_events) >= 1
    assert len(changed_events) >= 1

    changing_actual = changing_events[-1]
    changed_actual = changed_events[-1]

    changing_expected = changing_op_type_event(
        event_name="changing_op_type",
        timestamp=changing_actual.timestamp,
        ea=0x401000,
        n=1,
    )
    assert changing_actual == changing_expected

    changed_expected = op_type_changed_event(
        event_name="op_type_changed",
        timestamp=changed_actual.timestamp,
        ea=0x401000,
        n=1,
    )
    assert changed_actual == changed_expected


def test_op_type_changed_decimal(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that changing operand type to decimal triggers op_type events."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc

            test_ea = 0x401000
            idc.op_dec(test_ea, 1)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    changing_events = [e for e in event_list.root if isinstance(e, changing_op_type_event)]
    changed_events = [e for e in event_list.root if isinstance(e, op_type_changed_event)]

    assert len(changing_events) >= 1
    assert len(changed_events) >= 1

    changing_actual = changing_events[-1]
    changed_actual = changed_events[-1]

    changing_expected = changing_op_type_event(
        event_name="changing_op_type",
        timestamp=changing_actual.timestamp,
        ea=0x401000,
        n=1,
    )
    assert changing_actual == changing_expected

    changed_expected = op_type_changed_event(
        event_name="op_type_changed",
        timestamp=changed_actual.timestamp,
        ea=0x401000,
        n=1,
    )
    assert changed_actual == changed_expected


def test_op_type_changed_binary(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that changing operand type to binary triggers op_type events."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc

            test_ea = 0x401000
            idc.op_bin(test_ea, 1)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    changing_events = [e for e in event_list.root if isinstance(e, changing_op_type_event)]
    changed_events = [e for e in event_list.root if isinstance(e, op_type_changed_event)]

    assert len(changing_events) >= 1
    assert len(changed_events) >= 1

    changing_actual = changing_events[-1]
    changed_actual = changed_events[-1]

    changing_expected = changing_op_type_event(
        event_name="changing_op_type",
        timestamp=changing_actual.timestamp,
        ea=0x401000,
        n=1,
    )
    assert changing_actual == changing_expected

    changed_expected = op_type_changed_event(
        event_name="op_type_changed",
        timestamp=changed_actual.timestamp,
        ea=0x401000,
        n=1,
    )
    assert changed_actual == changed_expected
