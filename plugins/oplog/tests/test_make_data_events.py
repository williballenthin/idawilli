import textwrap
from pathlib import Path

import pytest

from conftest import run_ida_script
from oplog_events import EventList, make_data_event


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
