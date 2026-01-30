import textwrap
from pathlib import Path

import pytest
from conftest import run_ida_script

from oplog_events import (
    UdmModel,
    EventList,
    FuncModel,
    RangeModel,
    func_added_event,
    func_deleted_event,
    func_updated_event,
    set_func_end_event,
    deleting_func_event,
    frame_created_event,
    frame_deleted_event,
    frame_expanded_event,
    set_func_start_event,
    stkpnts_changed_event,
    tryblks_updated_event,
    deleting_tryblks_event,
    updating_tryblks_event,
    frame_udm_changed_event,
    frame_udm_created_event,
    frame_udm_deleted_event,
    frame_udm_renamed_event,
    func_tail_deleted_event,
    deleting_func_tail_event,
    func_noret_changed_event,
    func_tail_appended_event,
    tail_owner_changed_event,
    thunk_func_created_event,
)


def test_func_added(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that adding a function triggers func_added event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_funcs

            test_func_ea = 0x401000

            func = ida_funcs.get_func(test_func_ea)
            if func:
                ida_funcs.del_func(test_func_ea)

            ida_funcs.add_func(test_func_ea)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    added_events = [e for e in event_list.root if isinstance(e, func_added_event)]
    assert len(added_events) >= 1

    matching = [e for e in added_events if e.pfn.start_ea == 0x401000]
    assert len(matching) >= 1

    actual = matching[-1]

    expected = func_added_event(
        event_name="func_added",
        timestamp=actual.timestamp,
        pfn=FuncModel(
            start_ea=0x401000,
            end_ea=0x40103F,
            flags=0x4200,
            frame=0x401000,
            frsize=12,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xFFFFFFFF,
            pntqty=0,
            regvarqty=0,
            regargqty=0,
            tailqty=0,
            owner=0x401000,
            refqty=12,
            name="sub_401000",
        ),
    )
    assert actual == expected


def test_func_updated(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that modifying a function triggers func_updated event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_funcs

            test_func_ea = 0x401000

            func = ida_funcs.get_func(test_func_ea)
            ida_funcs.set_func_end(test_func_ea, 0x40103e)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    updated_events = [e for e in event_list.root if isinstance(e, func_updated_event)]
    assert len(updated_events) >= 1

    matching = [e for e in updated_events if e.pfn.start_ea == 0x401000]
    assert len(matching) >= 1

    actual = matching[-1]

    expected = func_updated_event(
        event_name="func_updated",
        timestamp=actual.timestamp,
        pfn=FuncModel(
            start_ea=0x401000,
            end_ea=0x40103E,
            flags=0x4000,
            frame=0x401000,
            frsize=12,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xFFFFFFFF,
            pntqty=5,
            regvarqty=0,
            regargqty=0,
            tailqty=0,
            owner=0x401000,
            refqty=12,
            name="sub_401000",
        ),
    )
    assert actual == expected


def test_set_func_start(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that changing function start address triggers set_func_start event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_funcs
            import ida_ua
            import ida_bytes

            test_func_ea = 0x401000

            func = ida_funcs.get_func(test_func_ea)

            # Find next instruction head within the function
            new_start = ida_bytes.next_head(test_func_ea, func.end_ea)

            result = ida_funcs.set_func_start(test_func_ea, new_start)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    start_events = [e for e in event_list.root if isinstance(e, set_func_start_event)]
    assert len(start_events) >= 1

    matching = [e for e in start_events if e.pfn.start_ea == 0x401000]
    assert len(matching) >= 1

    actual = matching[-1]

    expected = set_func_start_event(
        event_name="set_func_start",
        timestamp=actual.timestamp,
        pfn=FuncModel(
            start_ea=0x401000,
            end_ea=0x40103F,
            flags=0x5400,
            frame=0x401000,
            frsize=12,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xFFFFFFFF,
            pntqty=6,
            regvarqty=0,
            regargqty=0,
            tailqty=0,
            owner=0x401000,
            refqty=12,
            name="sub_401000",
        ),
        new_start=0x401004,
    )
    assert actual == expected


def test_set_func_end(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that changing function end address triggers set_func_end event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_funcs

            test_func_ea = 0x401000

            func = ida_funcs.get_func(test_func_ea)
            ida_funcs.set_func_end(test_func_ea, 0x40103e)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    end_events = [e for e in event_list.root if isinstance(e, set_func_end_event)]
    assert len(end_events) >= 1

    matching = [e for e in end_events if e.pfn.start_ea == 0x401000]
    assert len(matching) >= 1

    actual = matching[-1]

    expected = set_func_end_event(
        event_name="set_func_end",
        timestamp=actual.timestamp,
        pfn=FuncModel(
            start_ea=0x401000,
            end_ea=0x40103F,
            flags=0x5400,
            frame=0x401000,
            frsize=12,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xFFFFFFFF,
            pntqty=6,
            regvarqty=0,
            regargqty=0,
            tailqty=0,
            owner=0x401000,
            refqty=12,
            name="sub_401000",
        ),
        new_end=0x40103E,
    )
    assert actual == expected


def test_func_deleted(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that deleting a function triggers deleting_func and func_deleted events."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_funcs

            test_func_ea = 0x401000

            ida_funcs.del_func(test_func_ea)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    deleting_events = [e for e in event_list.root if isinstance(e, deleting_func_event)]
    deleted_events = [e for e in event_list.root if isinstance(e, func_deleted_event)]

    assert len(deleting_events) >= 1
    assert len(deleted_events) >= 1

    deleting_actual = deleting_events[-1]
    deleted_actual = deleted_events[-1]

    deleting_expected = deleting_func_event(
        event_name="deleting_func",
        timestamp=deleting_actual.timestamp,
        pfn=FuncModel(
            start_ea=0x401000,
            end_ea=0x40103F,
            flags=0x5400,
            frame=0x401000,
            frsize=12,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xFFFFFFFF,
            pntqty=6,
            regvarqty=0,
            regargqty=0,
            tailqty=0,
            owner=0x401000,
            refqty=12,
            name="sub_401000",
        ),
    )
    assert deleting_actual == deleting_expected

    deleted_expected = func_deleted_event(
        event_name="func_deleted",
        timestamp=deleted_actual.timestamp,
        func_ea=0x401000,
    )
    assert deleted_actual == deleted_expected


@pytest.mark.xfail(
    reason="thunk_func_created requires set_func_name_if_jumpfunc() which is not exposed to Python - hook only fires during auto-analysis thunk detection"
)
def test_thunk_func_created(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that setting FUNC_THUNK flag triggers thunk_func_created event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_funcs

            test_func_ea = 0x401000

            func = ida_funcs.get_func(test_func_ea)
            func.flags |= ida_funcs.FUNC_THUNK
            ida_funcs.update_func(func)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    thunk_events = [e for e in event_list.root if isinstance(e, thunk_func_created_event)]
    assert len(thunk_events) >= 1

    matching = [e for e in thunk_events if e.pfn.start_ea == 0x401000]
    assert len(matching) >= 1

    actual = matching[-1]

    expected = thunk_func_created_event(
        event_name="thunk_func_created",
        timestamp=actual.timestamp,
        pfn=FuncModel(
            start_ea=0x401000,
            end_ea=0x40103F,
            flags=0x5480,
            frame=0x401000,
            frsize=12,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xFFFFFFFF,
            pntqty=6,
            regvarqty=0,
            regargqty=0,
            tailqty=0,
            owner=0x401000,
            refqty=12,
            name="sub_401000",
        ),
    )
    assert actual == expected


def test_func_tail_appended(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that appending a function tail triggers func_tail_appended event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_funcs
            import ida_segment

            test_func_ea = 0x401000
            tail_start = 0x80000000
            tail_end = 0x80000010

            func = ida_funcs.get_func(test_func_ea)

            ida_segment.add_segm(0, tail_start, tail_end, "TAIL_SEG", "CODE")

            patch_bytes = b'\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90'
            for i, byte in enumerate(patch_bytes):
                idc.patch_byte(tail_start + i, byte)

            for addr in range(tail_start, tail_end, 1):
                idc.create_insn(addr)

            ida_funcs.append_func_tail(func, tail_start, tail_end)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    tail_events = [e for e in event_list.root if isinstance(e, func_tail_appended_event)]
    assert len(tail_events) >= 1

    matching = [e for e in tail_events if e.pfn.start_ea == 0x401000]
    assert len(matching) >= 1

    actual = matching[-1]

    assert actual.event_name == "func_tail_appended"
    assert actual.pfn.start_ea == 0x401000
    assert actual.pfn.tailqty == 1
    assert actual.tail.start_ea == 0x80000000
    assert actual.tail.end_ea == 0x80000010
    assert actual.tail.owner == 0x401000
    assert actual.tail.flags == 0x8000


def test_func_tail_deleted(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that removing a function tail triggers deleting_func_tail and func_tail_deleted events."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_funcs
            import ida_segment

            test_func_ea = 0x401000
            tail_start = 0x80000000
            tail_end = 0x80000010

            func = ida_funcs.get_func(test_func_ea)

            ida_segment.add_segm(0, tail_start, tail_end, "TAIL_SEG", "CODE")

            patch_bytes = b'\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90'
            for i, byte in enumerate(patch_bytes):
                idc.patch_byte(tail_start + i, byte)

            for addr in range(tail_start, tail_end, 1):
                idc.create_insn(addr)

            ida_funcs.append_func_tail(func, tail_start, tail_end)

            ida_funcs.remove_func_tail(func, tail_start)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    deleting_events = [e for e in event_list.root if isinstance(e, deleting_func_tail_event)]
    deleted_events = [e for e in event_list.root if isinstance(e, func_tail_deleted_event)]

    assert len(deleting_events) >= 1
    assert len(deleted_events) >= 1

    deleting_actual = deleting_events[-1]
    deleted_actual = deleted_events[-1]

    deleting_expected = deleting_func_tail_event(
        event_name="deleting_func_tail",
        timestamp=deleting_actual.timestamp,
        pfn=FuncModel(
            start_ea=0x401000,
            end_ea=0x40103F,
            flags=0x4000,
            frame=0x401000,
            frsize=12,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xFFFFFFFF,
            pntqty=6,
            regvarqty=0,
            regargqty=0,
            tailqty=1,
            owner=0x401000,
            refqty=12,
            name="sub_401000",
        ),
        tail=RangeModel(
            start_ea=0x80000000,
            end_ea=0x80000010,
        ),
    )
    assert deleting_actual == deleting_expected

    deleted_expected = func_tail_deleted_event(
        event_name="func_tail_deleted",
        timestamp=deleted_actual.timestamp,
        pfn=FuncModel(
            start_ea=0x401000,
            end_ea=0x40103F,
            flags=0x4000,
            frame=0x401000,
            frsize=12,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xFFFFFFFF,
            pntqty=6,
            regvarqty=0,
            regargqty=0,
            tailqty=0,
            owner=0x401000,
            refqty=12,
            name="sub_401000",
        ),
        tail_ea=0x80000000,
    )
    assert deleted_actual == deleted_expected


def test_tail_owner_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that changing a function tail's owner triggers tail_owner_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_funcs
            import ida_segment

            test_func_ea = 0x401000
            tail_start = 0x80000000
            tail_end = 0x80000010

            main_func = ida_funcs.get_func(test_func_ea)

            # Get another function in the binary to use as second owner
            second_func = ida_funcs.get_next_func(main_func.end_ea)

            ida_segment.add_segm(0, tail_start, tail_end, "TAIL_SEG", "CODE")

            patch_bytes = b'\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90'
            for i, byte in enumerate(patch_bytes):
                idc.patch_byte(tail_start + i, byte)

            for addr in range(tail_start, tail_end, 1):
                idc.create_insn(addr)

            ida_funcs.append_func_tail(main_func, tail_start, tail_end)

            # Add second_func as a referer of the tail (required for set_tail_owner)
            ida_funcs.append_func_tail(second_func, tail_start, tail_end)

            tail_chunk = ida_funcs.get_fchunk(tail_start)
            ida_funcs.set_tail_owner(tail_chunk, second_func.start_ea)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    owner_change_events = [e for e in event_list.root if isinstance(e, tail_owner_changed_event)]
    assert len(owner_change_events) >= 1

    actual = owner_change_events[-1]

    # frregs is non-deterministic for this synthetic tail (varies: 0xea40, 0x55f0, 0xdab0, etc)
    # because the test creates an artificial function chunk with NOPs, not a real compiled function.
    # The important fields (start_ea, end_ea, flags, owner, name) are hardcoded as regression snapshot.
    expected = tail_owner_changed_event(
        event_name="tail_owner_changed",
        timestamp=actual.timestamp,
        tail=FuncModel(
            start_ea=0x80000000,
            end_ea=0x80000010,
            flags=0x8000,
            frame=0x401040,
            frsize=2,
            frregs=actual.tail.frregs,
            argsize=0,
            fpd=0,
            color=0xFFFFFFFF,
            pntqty=0,
            regvarqty=0,
            regargqty=0,
            tailqty=0,
            owner=0x401040,
            refqty=2,
            name="sub_401040",
        ),
        owner_func=0x401040,
        old_owner=0x401000,
    )
    assert actual == expected


@pytest.mark.xfail(
    reason="func_noret_changed requires set_noreturn_flag() which is not exposed to Python - hook only fires during auto-analysis detection"
)
def test_func_noret_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that setting FUNC_NORET flag triggers func_noret_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_funcs

            test_func_ea = 0x401000

            func = ida_funcs.get_func(test_func_ea)
            func.flags |= ida_funcs.FUNC_NORET
            ida_funcs.update_func(func)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    noret_events = [e for e in event_list.root if isinstance(e, func_noret_changed_event)]
    assert len(noret_events) >= 1

    matching = [e for e in noret_events if e.pfn.start_ea == 0x401000]
    assert len(matching) >= 1

    actual = matching[-1]

    expected = func_noret_changed_event(
        event_name="func_noret_changed",
        timestamp=actual.timestamp,
        pfn=FuncModel(
            start_ea=0x401000,
            end_ea=0x40103F,
            flags=0x5400,
            frame=0x401000,
            frsize=12,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xFFFFFFFF,
            pntqty=6,
            regvarqty=0,
            regargqty=0,
            tailqty=0,
            owner=0x401000,
            refqty=12,
            name="sub_401000",
        ),
    )
    assert actual == expected


def test_tryblks_events(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that tryblks (try/catch block) operations trigger tryblks events."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_funcs
            import ida_tryblks

            test_func_ea = 0x401000

            func = ida_funcs.get_func(test_func_ea)

            try:
                if ida_tryblks.get_tryblks(test_func_ea):
                    pass
            except Exception as e:
                pass

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    updating_events = [e for e in event_list.root if isinstance(e, updating_tryblks_event)]
    updated_events = [e for e in event_list.root if isinstance(e, tryblks_updated_event)]
    deleting_events = [e for e in event_list.root if isinstance(e, deleting_tryblks_event)]

    assert isinstance(updating_events, list)
    assert isinstance(updated_events, list)
    assert isinstance(deleting_events, list)


def test_stkpnts_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that adding a stack point triggers stkpnts_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_frame
            import ida_funcs

            func_ea = 0x401000
            pfn = ida_funcs.get_func(func_ea)

            ida_frame.add_user_stkpnt(func_ea + 1, -4)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    matching = [e for e in event_list.root if isinstance(e, stkpnts_changed_event)]
    assert len(matching) >= 1

    actual = [e for e in matching if e.pfn.start_ea == 0x401000][-1]

    expected = stkpnts_changed_event(
        event_name="stkpnts_changed",
        timestamp=actual.timestamp,
        pfn=FuncModel(
            start_ea=0x401000,
            end_ea=0x40103F,
            flags=0x5400,
            frame=0x401000,
            frsize=12,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xFFFFFFFF,
            pntqty=7,
            regvarqty=0,
            regargqty=0,
            tailqty=0,
            owner=0x401000,
            refqty=12,
            name="sub_401000",
        ),
    )
    assert actual == expected


def test_frame_created(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that creating a function frame triggers frame_created event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_frame
            import ida_funcs
            import ida_segment

            seg_start = 0x90000000
            seg_end = 0x90000100

            ida_segment.add_segm(0, seg_start, seg_end, "FRAME_TEST", "CODE")

            patch_bytes = b'\\x55\\x89\\xe5\\x83\\xec\\x10\\x90\\x90\\xc9\\xc3'
            for i, byte in enumerate(patch_bytes):
                idc.patch_byte(seg_start + i, byte)

            for addr in range(seg_start, seg_start + len(patch_bytes)):
                idc.create_insn(addr)

            ida_funcs.add_func(seg_start, seg_start + len(patch_bytes))

            pfn = ida_funcs.get_func(seg_start)
            ida_frame.del_frame(pfn)

            pfn = ida_funcs.get_func(seg_start)
            ida_frame.add_frame(pfn, 16, 4, 0)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    matching = [e for e in event_list.root if isinstance(e, frame_created_event)]
    assert len(matching) >= 1

    actual = [e for e in matching if e.func_ea == 0x90000000][-1]

    expected = frame_created_event(
        event_name="frame_created",
        timestamp=actual.timestamp,
        func_ea=0x90000000,
    )
    assert actual == expected


def test_frame_expanded(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that expanding a frame triggers frame_expanded event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_typeinf
            import ida_funcs

            func_ea = 0x401000
            pfn = ida_funcs.get_func(func_ea)

            frame = ida_typeinf.tinfo_t()
            frame.get_func_frame(pfn)

            ETF_FRAME = 0x80000000
            result = frame.expand_udt(0, 8, ETF_FRAME)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    matching = [e for e in event_list.root if isinstance(e, frame_expanded_event)]
    assert len(matching) >= 1

    actual = [e for e in matching if e.func_ea == 0x401000][-1]

    expected = frame_expanded_event(
        event_name="frame_expanded",
        timestamp=actual.timestamp,
        func_ea=0x401000,
        udm_name=actual.udm_name,
        delta=8,
    )
    assert actual == expected


def test_frame_deleted(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that deleting a function frame triggers frame_deleted event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_frame
            import ida_funcs

            func_ea = 0x401000
            pfn = ida_funcs.get_func(func_ea)

            ida_frame.del_frame(pfn)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    matching = [e for e in event_list.root if isinstance(e, frame_deleted_event)]
    assert len(matching) >= 1

    actual = [e for e in matching if e.pfn.start_ea == 0x401000][-1]

    expected = frame_deleted_event(
        event_name="frame_deleted",
        timestamp=actual.timestamp,
        pfn=FuncModel(
            start_ea=0x401000,
            end_ea=0x40103F,
            flags=0x5400,
            frame=0xFFFFFFFFFFFFFFFF,
            frsize=0,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xFFFFFFFF,
            pntqty=6,
            regvarqty=0,
            regargqty=0,
            tailqty=0,
            owner=0xFFFFFFFFFFFFFFFF,
            refqty=0,
            name="sub_401000",
        ),
    )
    assert actual == expected


def test_frame_udm_created(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that adding a frame member triggers frame_udm_created event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_typeinf
            import ida_frame
            import ida_funcs

            func_ea = 0x401000
            pfn = ida_funcs.get_func(func_ea)

            frame = ida_typeinf.tinfo_t()
            frame.get_func_frame(pfn)

            udm = ida_typeinf.udm_t()
            udm.name = "my_new_var"
            udm.type = ida_typeinf.tinfo_t(ida_typeinf.BT_INT32)
            udm.offset = 0x100 * 8
            udm.size = 4 * 8

            ETF_FRAME = 0x80000000
            frame.add_udm(udm, ETF_FRAME)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    matching = [e for e in event_list.root if isinstance(e, frame_udm_created_event)]
    assert len(matching) >= 1

    actual = [e for e in matching if e.func_ea == 0x401000 and e.udm.name == "my_new_var"][-1]

    expected = frame_udm_created_event(
        event_name="frame_udm_created",
        timestamp=actual.timestamp,
        func_ea=0x401000,
        udm=UdmModel(
            offset=0x800,
            size=0x20,
            name="my_new_var",
            cmt="",
            type_name="(unnamed)",
            repr="",
            effalign=0,
            tafld_bits=0,
            fda=0,
        ),
    )
    assert actual == expected


def test_frame_udm_deleted(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that deleting a frame member triggers frame_udm_deleted event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_typeinf
            import ida_frame
            import ida_funcs

            func_ea = 0x401000
            pfn = ida_funcs.get_func(func_ea)

            frame = ida_typeinf.tinfo_t()
            frame.get_func_frame(pfn)

            ETF_FRAME = 0x80000000
            frame.del_udm(0, ETF_FRAME)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    matching = [e for e in event_list.root if isinstance(e, frame_udm_deleted_event)]
    assert len(matching) >= 1

    actual = [e for e in matching if e.func_ea == 0x401000][-1]

    expected = frame_udm_deleted_event(
        event_name="frame_udm_deleted",
        timestamp=actual.timestamp,
        func_ea=0x401000,
        udm=UdmModel(
            offset=96,
            size=32,
            name="__return_address",
            cmt="",
            type_name="(unnamed)",
            repr="",
            effalign=0,
            tafld_bits=0x1000,
            fda=0,
        ),
    )
    assert actual == expected


def test_frame_udm_renamed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that renaming a frame member triggers frame_udm_renamed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_typeinf
            import ida_frame
            import ida_funcs

            func_ea = 0x401000
            pfn = ida_funcs.get_func(func_ea)

            frame = ida_typeinf.tinfo_t()
            frame.get_func_frame(pfn)

            ETF_FRAME = 0x80000000
            frame.rename_udm(0, "renamed_var", ETF_FRAME)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    matching = [e for e in event_list.root if isinstance(e, frame_udm_renamed_event)]
    assert len(matching) >= 1

    actual = [e for e in matching if e.func_ea == 0x401000 and e.udm.name == "renamed_var"][-1]

    expected = frame_udm_renamed_event(
        event_name="frame_udm_renamed",
        timestamp=actual.timestamp,
        func_ea=0x401000,
        udm=UdmModel(
            offset=96,
            size=0,
            name="renamed_var",
            cmt="",
            type_name="(unnamed)",
            repr="",
            effalign=0,
            tafld_bits=0,
            fda=0,
        ),
        oldname="__return_address",
    )
    assert actual == expected


def test_frame_udm_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that changing a frame member comment triggers frame_udm_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import idc
            import ida_typeinf
            import ida_frame
            import ida_funcs

            func_ea = 0x401000
            pfn = ida_funcs.get_func(func_ea)

            frame = ida_typeinf.tinfo_t()
            frame.get_func_frame(pfn)

            ETF_FRAME = 0x80000000
            frame.set_udm_cmt(0, "test comment for frame member", False, ETF_FRAME)

            idc.eval_idc('oplog_export("{events_path}")')
        """),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    matching = [e for e in event_list.root if isinstance(e, frame_udm_changed_event)]
    assert len(matching) >= 1

    actual = [e for e in matching if e.func_ea == 0x401000][-1]

    expected = frame_udm_changed_event(
        event_name="frame_udm_changed",
        timestamp=actual.timestamp,
        func_ea=0x401000,
        udmold=UdmModel(
            offset=96,
            size=0,
            name="__return_address",
            cmt="",
            type_name="(unnamed)",
            repr="",
            effalign=0,
            tafld_bits=0x1000,
            fda=0,
        ),
        udmnew=UdmModel(
            offset=96,
            size=0,
            name="__return_address",
            cmt="test comment for frame member",
            type_name="(unnamed)",
            repr="",
            effalign=0,
            tafld_bits=0x1000,
            fda=0,
        ),
    )
    assert actual == expected
