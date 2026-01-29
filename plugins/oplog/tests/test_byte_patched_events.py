import textwrap
from pathlib import Path

from conftest import run_ida_script
from oplog_events import EventList, byte_patched_event


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
        old_value=139,
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
        old_value=139,
    )
    assert matching_base[-1] == expected_1

    expected_2 = byte_patched_event(
        event_name="byte_patched",
        timestamp=matching_plus1[-1].timestamp,
        ea=0x401001,
        old_value=84,
    )
    assert matching_plus1[-1] == expected_2

    expected_3 = byte_patched_event(
        event_name="byte_patched",
        timestamp=matching_plus2[-1].timestamp,
        ea=0x401002,
        old_value=36,
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
