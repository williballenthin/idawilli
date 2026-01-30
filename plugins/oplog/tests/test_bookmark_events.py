import textwrap
from pathlib import Path

import pytest

from conftest import run_ida_script
from oplog_events import (
    EventList,
    bookmark_changed_event,
)


def test_bookmark_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that adding a bookmark triggers bookmark_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_moves
            import ida_kernwin

            ea = 0x401000

            place_id = ida_kernwin.get_place_class_id("idaplace_t")
            place_template = ida_kernwin.get_place_class_template(place_id)

            idaplace = ida_kernwin.place_t_as_idaplace_t(place_template)
            idaplace.ea = ea
            idaplace.lnnum = 0

            entry = ida_moves.lochist_entry_t()
            entry.set_place(idaplace)

            ida_moves.bookmarks_t_mark(entry, 1, None, "Test bookmark", None)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    bookmark_events = [e for e in event_list.root if isinstance(e, bookmark_changed_event)]

    assert len(bookmark_events) >= 1

    actual = bookmark_events[-1]
    expected = bookmark_changed_event(
        event_name="bookmark_changed",
        timestamp=actual.timestamp,
        index=1,
        ea=0x401000,
        desc="Test bookmark",
        operation=0,
    )
    assert actual == expected


@pytest.mark.xfail(reason="bookmarks_t_erase requires GUI typed_bookmarks_t context, unavailable in headless mode")
def test_bookmark_changed_delete(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that deleting a bookmark triggers bookmark_changed event.

    Note: This test is xfail because bookmark deletion requires a typed_bookmarks_t
    context that is only created for GUI widgets. In headless mode, the add operation
    works but delete fails silently because there's no typed_bookmarks_t to find.
    """
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_moves
            import ida_kernwin

            ea = 0x401000

            place_id = ida_kernwin.get_place_class_id("idaplace_t")
            place_template = ida_kernwin.get_place_class_template(place_id)

            idaplace = ida_kernwin.place_t_as_idaplace_t(place_template)
            idaplace.ea = ea
            idaplace.lnnum = 0

            entry = ida_moves.lochist_entry_t()
            entry.set_place(idaplace)

            ida_moves.bookmarks_t_mark(entry, 0, None, "Bookmark to delete", None)

            ida_moves.bookmarks_t_mark(entry, 0, None, "", None)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    bookmark_events = [e for e in event_list.root if isinstance(e, bookmark_changed_event)]

    assert len(bookmark_events) >= 2

    delete_event = bookmark_events[-1]
    expected = bookmark_changed_event(
        event_name="bookmark_changed",
        timestamp=delete_event.timestamp,
        index=0,
        ea=0x401000,
        desc="",
        operation=2,
    )
    assert delete_event == expected
