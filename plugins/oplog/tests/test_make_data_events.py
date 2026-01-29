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
        flags=536871936,
        tid=18446744073709551615,
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
        flags=1024,
        tid=18446744073709551615,
        len=1,
    )
    assert actual == expected


@pytest.mark.xfail(reason="make_data does not fire as expected")
def test_make_data_word(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that creating a word triggers make_data event.
    """
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_bytes

            test_ea = 0x401020
            ida_bytes.del_items(test_ea, ida_bytes.DELIT_SIMPLE)
            idc.create_word(test_ea)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    make_data_events = [e for e in event_list.root if isinstance(e, make_data_event)]

    matching = [e for e in make_data_events if e.ea == 0x401020]
    assert len(matching) >= 1, "No make_data event found for address 0x401020"

    actual = matching[-1]

    expected = make_data_event(
        event_name="make_data",
        timestamp=actual.timestamp,
        ea=0x401020,
        flags=2048,
        tid=18446744073709551615,
        len=2,
    )
    assert actual == expected
