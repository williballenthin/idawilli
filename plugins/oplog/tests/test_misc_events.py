import textwrap
from pathlib import Path

import pytest

from conftest import run_ida_script
from oplog_events import (
    EventList,
    determined_main_event,
    extlang_changed_event,
    idasgn_matched_ea_event,
)


@pytest.mark.xfail(reason="determined_main only fires from IDA's internal analysis engine, not via Python API")
def test_determined_main(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that setting the main function triggers determined_main event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_ida

            ida_ida.inf_set_main(0x401000)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    matching = [e for e in event_list.root if isinstance(e, determined_main_event)]
    assert len(matching) >= 1

    actual = matching[-1]

    expected = determined_main_event(
        event_name="determined_main",
        timestamp=actual.timestamp,
        main=0x401000,
    )
    assert actual == expected


@pytest.mark.xfail(reason="enable_extlang_python may crash when disabling Python while running Python code")
def test_extlang_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that changing the extlang triggers extlang_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    matching = [e for e in event_list.root if isinstance(e, extlang_changed_event)]
    assert len(matching) >= 1

    actual = matching[-1]

    assert actual.event_name == "extlang_changed"
    assert actual.kind == 2


@pytest.mark.xfail(reason="idasgn_matched_ea requires FLIRT signature files matching the test binary")
def test_idasgn_matched_ea(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that FLIRT signature matching triggers idasgn_matched_ea event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_funcs

            func_ea = 0x401000
            ida_funcs.apply_idasgn_to("vc32rtf", func_ea, False)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    matching = [e for e in event_list.root if isinstance(e, idasgn_matched_ea_event)]
    assert len(matching) >= 1

    actual = matching[-1]

    assert actual.event_name == "idasgn_matched_ea"
    assert actual.ea == 0x401000