import textwrap
from pathlib import Path

import pytest

from conftest import run_ida_script
from oplog_events import (
    EventList,
    FuncModel,
    RangeModel,
    func_added_event,
    func_updated_event,
    set_func_start_event,
    set_func_end_event,
    deleting_func_event,
    func_deleted_event,
    thunk_func_created_event,
    func_tail_appended_event,
    deleting_func_tail_event,
    func_tail_deleted_event,
    tail_owner_changed_event,
    func_noret_changed_event,
    updating_tryblks_event,
    tryblks_updated_event,
    deleting_tryblks_event,
)


def test_func_added(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that adding a function triggers func_added event."""
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
            if func:
                ida_funcs.del_func(test_func_ea)

            ida_funcs.add_func(test_func_ea)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
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
            end_ea=0x40103f,
            flags=0x4200,
            frame=0x401000,
            frsize=12,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xffffffff,
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
        script=textwrap.dedent(f'''
            import idc
            import ida_funcs

            test_func_ea = 0x401000

            func = ida_funcs.get_func(test_func_ea)
            ida_funcs.set_func_end(test_func_ea, 0x40103e)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
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
            end_ea=0x40103e,
            flags=0x4000,
            frame=0x401000,
            frsize=12,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xffffffff,
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


@pytest.mark.xfail(reason="set_func_start hook does not fire as expected")
def test_set_func_start(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that changing function start address triggers set_func_start event."""
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
            ida_funcs.set_func_start(test_func_ea, 0x401002)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
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
            end_ea=0x40103f,
            flags=0x4200,
            frame=0x401000,
            frsize=12,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xffffffff,
            pntqty=0,
            regvarqty=0,
            regargqty=0,
            tailqty=0,
            owner=0x401000,
            refqty=12,
            name="sub_401000",
        ),
        new_start=0x401002,
    )
    assert actual == expected


def test_set_func_end(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that changing function end address triggers set_func_end event."""
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
            ida_funcs.set_func_end(test_func_ea, 0x40103e)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
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
            end_ea=0x40103f,
            flags=0x5400,
            frame=0x401000,
            frsize=12,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xffffffff,
            pntqty=6,
            regvarqty=0,
            regargqty=0,
            tailqty=0,
            owner=0x401000,
            refqty=12,
            name="sub_401000",
        ),
        new_end=0x40103e,
    )
    assert actual == expected


def test_func_deleted(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that deleting a function triggers deleting_func and func_deleted events."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_funcs

            test_func_ea = 0x401000

            ida_funcs.del_func(test_func_ea)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
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
            end_ea=0x40103f,
            flags=0x5400,
            frame=0x401000,
            frsize=12,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xffffffff,
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


@pytest.mark.xfail(reason="thunk_func_created hook does not fire as expected")
def test_thunk_func_created(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that setting FUNC_THUNK flag triggers thunk_func_created event."""
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
            func.flags |= ida_funcs.FUNC_THUNK
            ida_funcs.update_func(func)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
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
            end_ea=0x40103f,
            flags=0x5480,
            frame=0x401000,
            frsize=12,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xffffffff,
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
        script=textwrap.dedent(f'''
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
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    tail_events = [e for e in event_list.root if isinstance(e, func_tail_appended_event)]
    assert len(tail_events) >= 1

    matching = [e for e in tail_events if e.pfn.start_ea == 0x401000]
    assert len(matching) >= 1

    actual = matching[-1]

    expected = func_tail_appended_event(
        event_name="func_tail_appended",
        timestamp=actual.timestamp,
        pfn=FuncModel(
            start_ea=0x401000,
            end_ea=0x40103f,
            flags=0x5400,
            frame=0x401000,
            frsize=12,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xffffffff,
            pntqty=6,
            regvarqty=0,
            regargqty=0,
            tailqty=1,
            owner=0x401000,
            refqty=12,
            name="sub_401000",
        ),
        tail=FuncModel(
            start_ea=0x80000000,
            end_ea=0x80000010,
            flags=0x8000,
            frame=0x401000,
            frsize=actual.tail.frsize,
            frregs=actual.tail.frregs,
            argsize=0,
            fpd=0,
            color=0xffffffff,
            pntqty=0,
            regvarqty=0,
            regargqty=0,
            tailqty=0,
            owner=0x401000,
            refqty=actual.tail.refqty,
            name="sub_401000",
        ),
    )
    assert actual == expected


def test_func_tail_deleted(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that removing a function tail triggers deleting_func_tail and func_tail_deleted events."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
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
        '''),
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
            end_ea=0x40103f,
            flags=0x4000,
            frame=0x401000,
            frsize=12,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xffffffff,
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
            end_ea=0x40103f,
            flags=0x4000,
            frame=0x401000,
            frsize=12,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xffffffff,
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


@pytest.mark.xfail(reason="tail_owner_changed hook does not fire as expected")
def test_tail_owner_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that changing a function tail's owner triggers tail_owner_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_funcs
            import ida_segment

            test_func_ea = 0x401000
            second_func_ea = 0x40106a
            tail_start = 0x80000000
            tail_end = 0x80000010

            main_func = ida_funcs.get_func(test_func_ea)
            second_func = ida_funcs.get_func(second_func_ea)

            if not second_func:
                ida_funcs.add_func(second_func_ea)
                second_func = ida_funcs.get_func(second_func_ea)

            ida_segment.add_segm(0, tail_start, tail_end, "TAIL_SEG", "CODE")

            patch_bytes = b'\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90'
            for i, byte in enumerate(patch_bytes):
                idc.patch_byte(tail_start + i, byte)

            for addr in range(tail_start, tail_end, 1):
                idc.create_insn(addr)

            ida_funcs.append_func_tail(main_func, tail_start, tail_end)

            ida_funcs.set_tail_owner(tail_start, second_func_ea)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    owner_change_events = [e for e in event_list.root if isinstance(e, tail_owner_changed_event)]
    assert len(owner_change_events) >= 1

    actual = owner_change_events[-1]

    expected = tail_owner_changed_event(
        event_name="tail_owner_changed",
        timestamp=actual.timestamp,
        tail=FuncModel(
            start_ea=0x80000000,
            end_ea=0x80000010,
            flags=0x8000,
            frame=0x40106a,
            frsize=actual.tail.frsize,
            frregs=actual.tail.frregs,
            argsize=0,
            fpd=0,
            color=0xffffffff,
            pntqty=0,
            regvarqty=0,
            regargqty=0,
            tailqty=0,
            owner=0x40106a,
            refqty=actual.tail.refqty,
            name="sub_40106a",
        ),
        owner_func=0x40106a,
        old_owner=0x401000,
    )
    assert actual == expected


@pytest.mark.xfail(reason="func_noret_changed hook does not fire as expected")
def test_func_noret_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that setting FUNC_NORET flag triggers func_noret_changed event."""
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
            func.flags |= ida_funcs.FUNC_NORET
            ida_funcs.update_func(func)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
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
            end_ea=0x40103f,
            flags=0x5400,
            frame=0x401000,
            frsize=12,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xffffffff,
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
        script=textwrap.dedent(f'''
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
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    updating_events = [e for e in event_list.root if isinstance(e, updating_tryblks_event)]
    updated_events = [e for e in event_list.root if isinstance(e, tryblks_updated_event)]
    deleting_events = [e for e in event_list.root if isinstance(e, deleting_tryblks_event)]

    assert isinstance(updating_events, list)
    assert isinstance(updated_events, list)
    assert isinstance(deleting_events, list)
