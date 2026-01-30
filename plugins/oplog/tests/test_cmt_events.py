import textwrap
from pathlib import Path

from conftest import run_ida_script
from oplog_events import (
    EventList,
    RangeModel,
    changing_cmt_event,
    cmt_changed_event,
    changing_range_cmt_event,
    range_cmt_changed_event,
    extra_cmt_changed_event,
)


def test_cmt_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that setting a comment triggers changing_cmt and cmt_changed events."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc

            test_ea = 0x401000
            idc.set_cmt(test_ea, "test comment", False)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    changing_events = [e for e in event_list.root if isinstance(e, changing_cmt_event)]
    changed_events = [e for e in event_list.root if isinstance(e, cmt_changed_event)]

    assert len(changing_events) >= 1
    assert len(changed_events) >= 1

    changing_actual = changing_events[-1]
    changed_actual = changed_events[-1]

    changing_expected = changing_cmt_event(
        event_name="changing_cmt",
        timestamp=changing_actual.timestamp,
        ea=0x401000,
        repeatable_cmt=False,
        newcmt="test comment",
    )
    assert changing_actual == changing_expected

    changed_expected = cmt_changed_event(
        event_name="cmt_changed",
        timestamp=changed_actual.timestamp,
        ea=0x401000,
        repeatable_cmt=False,
    )
    assert changed_actual == changed_expected


def test_range_cmt_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that setting a function comment triggers changing_range_cmt and range_cmt_changed events."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_funcs

            test_func_ea = 0x401000
            func = ida_funcs.get_func(test_func_ea)
            ida_funcs.set_func_cmt(func, "function comment", False)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    changing_events = [e for e in event_list.root if isinstance(e, changing_range_cmt_event)]
    changed_events = [e for e in event_list.root if isinstance(e, range_cmt_changed_event)]

    assert len(changing_events) >= 1
    assert len(changed_events) >= 1

    changing_actual = changing_events[-1]
    changed_actual = changed_events[-1]

    changing_expected = changing_range_cmt_event(
        event_name="changing_range_cmt",
        timestamp=changing_actual.timestamp,
        kind=1,
        a=RangeModel(start_ea=0x401000, end_ea=0x40103f),
        cmt="function comment",
        repeatable=False,
    )
    assert changing_actual == changing_expected

    changed_expected = range_cmt_changed_event(
        event_name="range_cmt_changed",
        timestamp=changed_actual.timestamp,
        kind=1,
        a=RangeModel(start_ea=0x401000, end_ea=0x40103f),
        cmt="function comment",
        repeatable=False,
    )
    assert changed_actual == changed_expected


def test_extra_cmt_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that setting an anterior extra comment triggers extra_cmt_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_lines

            test_ea = 0x401000
            ida_lines.update_extra_cmt(test_ea, ida_lines.E_PREV, "anterior comment")

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    extra_cmt_events = [e for e in event_list.root if isinstance(e, extra_cmt_changed_event)]

    assert len(extra_cmt_events) >= 1

    actual = extra_cmt_events[-1]

    expected = extra_cmt_changed_event(
        event_name="extra_cmt_changed",
        timestamp=actual.timestamp,
        ea=0x401000,
        line_idx=0x3e8,
        cmt="anterior comment",
    )
    assert actual == expected
