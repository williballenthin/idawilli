import textwrap
from pathlib import Path

import pytest

from conftest import run_ida_script
from oplog_events import (
    EventList,
    dirtree_mkdir_event,
    dirtree_rmdir_event,
    dirtree_link_event,
    dirtree_move_event,
    dirtree_rank_event,
    dirtree_rminode_event,
    dirtree_segm_moved_event,
)


def test_dirtree_mkdir(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that creating a directory in the tree triggers dirtree_mkdir_event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_dirtree

            # Get the names dirtree
            dt = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_NAMES)
            if dt:
                dt.mkdir("TestDir")

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
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
        script=textwrap.dedent(f'''
            import idc
            import ida_dirtree

            dt = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_NAMES)
            if dt:
                dt.mkdir("TestDir")
                dt.rmdir("TestDir")
            idc.eval_idc('oplog_export("{events_path}")')
        '''),
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
        script=textwrap.dedent(f'''
            import idc
            import ida_dirtree

            dt = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_NAMES)
            if dt:
                dt.mkdir("TestDir")
                dt.link("TestDir")
            idc.eval_idc('oplog_export("{events_path}")')
        '''),
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
        script=textwrap.dedent(f'''
            import idc
            import ida_dirtree

            dt = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_NAMES)
            if dt:
                dt.mkdir("OldName")
                dt.rename("OldName", "NewName")
            idc.eval_idc('oplog_export("{events_path}")')
        '''),
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
        script=textwrap.dedent(f'''
            import idc
            import ida_dirtree

            dt = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_NAMES)
            if dt:
                dt.mkdir("TestDir")
                dt.change_rank("TestDir", 5)
            idc.eval_idc('oplog_export("{events_path}")')
        '''),
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
        script=textwrap.dedent(f'''
            import idc
            import ida_dirtree

            dt = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_NAMES)
            if dt:
                dt.mkdir("TestDir")
                dt.rmdir("TestDir")
            idc.eval_idc('oplog_export("{events_path}")')
        '''),
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
        script=textwrap.dedent(f'''
            import idc
            import ida_segment

            delta = 0x1000
            ida_segment.rebase_program(delta, ida_segment.MSF_FIXONCE)
            idc.eval_idc('oplog_export("{events_path}")')
        '''),
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
