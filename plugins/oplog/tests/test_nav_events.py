import textwrap
from pathlib import Path

import pytest
from conftest import run_ida_script

from oplog_events import (
    EventList,
    renamed_event,
    dirtree_link_event,
    dirtree_move_event,
    dirtree_rank_event,
    dirtree_mkdir_event,
    dirtree_rmdir_event,
    dirtree_rminode_event,
    bookmark_changed_event,
    dirtree_segm_moved_event,
    item_color_changed_event,
)


def test_bookmark_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that adding a bookmark triggers bookmark_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
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
        """),
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
        script=textwrap.dedent(f"""
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
        """),
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


def test_item_color_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that setting item color triggers item_color_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc

            test_ea = 0x401000
            idc.set_color(test_ea, idc.CIC_ITEM, 0x0000FF)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    color_events = [e for e in event_list.root if isinstance(e, item_color_changed_event)]

    matching = [e for e in color_events if e.ea == 0x401000]
    assert len(matching) >= 1

    actual = matching[-1]

    expected = item_color_changed_event(
        event_name="item_color_changed",
        timestamp=actual.timestamp,
        ea=0x401000,
        color=0xFF,
    )
    assert actual == expected


def test_item_color_reset(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that resetting item color (DEFCOLOR) triggers item_color_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc

            test_ea = 0x401000
            idc.set_color(test_ea, idc.CIC_ITEM, 0xFF0000)
            idc.set_color(test_ea, idc.CIC_ITEM, idc.DEFCOLOR)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    color_events = [e for e in event_list.root if isinstance(e, item_color_changed_event)]

    matching = [e for e in color_events if e.ea == 0x401000]
    assert len(matching) >= 2

    actual = matching[-1]

    expected = item_color_changed_event(
        event_name="item_color_changed",
        timestamp=actual.timestamp,
        ea=0x401000,
        color=0xFFFFFFFF,
    )
    assert actual == expected


def test_dirtree_mkdir(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that creating a directory in the tree triggers dirtree_mkdir_event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_dirtree

            # Get the names dirtree
            dt = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_NAMES)
            if dt:
                dt.mkdir("TestDir")

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    mkdir_events = [e for e in event_list.root if isinstance(e, dirtree_mkdir_event)]

    assert len(mkdir_events) >= 1

    actual = mkdir_events[-1]
    expected = dirtree_mkdir_event(
        event_name="dirtree_mkdir",
        timestamp=actual.timestamp,
        path="TestDir",
    )
    assert actual == expected


def test_dirtree_rmdir(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that removing a directory from the tree triggers dirtree_rmdir_event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_dirtree

            dt = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_NAMES)
            if dt:
                dt.mkdir("TestDir")
                dt.rmdir("TestDir")
            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    rmdir_events = [e for e in event_list.root if isinstance(e, dirtree_rmdir_event)]

    assert len(rmdir_events) >= 1

    actual = rmdir_events[-1]
    expected = dirtree_rmdir_event(
        event_name="dirtree_rmdir",
        timestamp=actual.timestamp,
        path="TestDir",
    )
    assert actual == expected


@pytest.mark.xfail(reason="dirtree_link does not fire via API link/unlink calls")
def test_dirtree_link(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that linking/referencing in tree triggers dirtree_link_event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_dirtree

            dt = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_NAMES)
            if dt:
                dt.mkdir("TestDir")
                dt.link("TestDir")
            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    link_events = [e for e in event_list.root if isinstance(e, dirtree_link_event)]

    assert len(link_events) >= 1

    actual = link_events[-1]
    expected = dirtree_link_event(
        event_name="dirtree_link",
        timestamp=actual.timestamp,
        path="TestDir",
        link=True,
    )
    assert actual == expected


def test_dirtree_move(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that moving/renaming in tree triggers dirtree_move_event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_dirtree

            dt = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_NAMES)
            if dt:
                dt.mkdir("OldName")
                dt.rename("OldName", "NewName")
            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    move_events = [e for e in event_list.root if isinstance(e, dirtree_move_event)]

    assert len(move_events) >= 1

    actual = move_events[-1]
    expected = dirtree_move_event(
        event_name="dirtree_move",
        timestamp=actual.timestamp,
        _from="OldName",
        to="NewName",
    )
    assert actual == expected


def test_dirtree_rank(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that changing rank/order in tree triggers dirtree_rank_event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_dirtree

            dt = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_NAMES)
            if dt:
                dt.mkdir("TestDir")
                dt.change_rank("TestDir", 5)
            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    rank_events = [e for e in event_list.root if isinstance(e, dirtree_rank_event)]

    assert len(rank_events) >= 1

    actual = rank_events[-1]
    expected = dirtree_rank_event(
        event_name="dirtree_rank",
        timestamp=actual.timestamp,
        path="TestDir",
        rank=5,
    )
    assert actual == expected


@pytest.mark.xfail(reason="dirtree_rminode does not fire via API rmdir call")
def test_dirtree_rminode(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that removing an inode from tree triggers dirtree_rminode_event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_dirtree

            dt = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_NAMES)
            if dt:
                dt.mkdir("TestDir")
                dt.rmdir("TestDir")
            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    rminode_events = [e for e in event_list.root if isinstance(e, dirtree_rminode_event)]

    assert len(rminode_events) >= 1

    actual = rminode_events[-1]
    expected = dirtree_rminode_event(
        event_name="dirtree_rminode",
        timestamp=actual.timestamp,
        inode=actual.inode,
    )
    assert actual == expected


def test_dirtree_segm_moved(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that segment move in tree triggers dirtree_segm_moved_event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_segment

            delta = 0x1000
            ida_segment.rebase_program(delta, ida_segment.MSF_FIXONCE)
            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    segm_moved_events = [e for e in event_list.root if isinstance(e, dirtree_segm_moved_event)]

    assert len(segm_moved_events) >= 1

    actual = segm_moved_events[-1]
    expected = dirtree_segm_moved_event(
        event_name="dirtree_segm_moved",
        timestamp=actual.timestamp,
    )
    assert actual == expected


def test_rename_captures_event(test_binary: Path, temp_idauser: Path, work_dir: Path):
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=temp_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc

            entry = idc.get_inf_attr(idc.INF_START_EA)
            idc.set_name(entry, "test_renamed_entry")
            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())

    renamed_events = [e for e in event_list.root if isinstance(e, renamed_event)]
    assert len(renamed_events) >= 1

    matching = [e for e in renamed_events if e.new_name == "test_renamed_entry"]
    assert len(matching) >= 1

    actual = matching[-1]

    expected = renamed_event(
        event_name="renamed",
        timestamp=actual.timestamp,
        ea=0x401820,
        new_name="test_renamed_entry",
        local_name=False,
        old_name="start",
    )
    assert actual == expected
