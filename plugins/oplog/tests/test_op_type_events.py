import textwrap
from pathlib import Path

from conftest import run_ida_script
from oplog_events import (
    EventList,
    changing_op_type_event,
    op_type_changed_event,
)


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
