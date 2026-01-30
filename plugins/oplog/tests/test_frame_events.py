import textwrap
from pathlib import Path

import pytest

from conftest import run_ida_script
from oplog_events import (
    EventList,
    FuncModel,
    UdmModel,
    stkpnts_changed_event,
    frame_created_event,
    frame_expanded_event,
    frame_deleted_event,
    frame_udm_created_event,
    frame_udm_deleted_event,
    frame_udm_renamed_event,
    frame_udm_changed_event,
)


def test_stkpnts_changed(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that adding a stack point triggers stkpnts_changed event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_frame
            import ida_funcs

            func_ea = 0x401000
            pfn = ida_funcs.get_func(func_ea)

            ida_frame.add_user_stkpnt(func_ea + 1, -4)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
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
            end_ea=0x40103f,
            flags=0x5400,
            frame=0x401000,
            frsize=12,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xffffffff,
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
        script=textwrap.dedent(f'''
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
        '''),
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
        script=textwrap.dedent(f'''
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
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    matching = [e for e in event_list.root if isinstance(e, frame_expanded_event)]
    assert len(matching) >= 1

    actual = [e for e in matching if e.func_ea == 0x401000][-1]

    expected = frame_expanded_event(
        event_name="frame_expanded",
        timestamp=actual.timestamp,
        func_ea=0x401000,
        udm_tid=actual.udm_tid,
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
        script=textwrap.dedent(f'''
            import idc
            import ida_frame
            import ida_funcs

            func_ea = 0x401000
            pfn = ida_funcs.get_func(func_ea)

            ida_frame.del_frame(pfn)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
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
            end_ea=0x40103f,
            flags=0x5400,
            frame=0xffffffffffffffff,
            frsize=0,
            frregs=0,
            argsize=0,
            fpd=0,
            color=0xffffffff,
            pntqty=6,
            regvarqty=0,
            regargqty=0,
            tailqty=0,
            owner=0xffffffffffffffff,
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
        script=textwrap.dedent(f'''
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
        '''),
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
            offset=2048,
            size=32,
            name="my_new_var",
            cmt="",
            tid=0xffffffffffffffff,
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
        script=textwrap.dedent(f'''
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
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    matching = [e for e in event_list.root if isinstance(e, frame_udm_deleted_event)]
    assert len(matching) >= 1

    actual = [e for e in matching if e.func_ea == 0x401000][-1]

    expected = frame_udm_deleted_event(
        event_name="frame_udm_deleted",
        timestamp=actual.timestamp,
        func_ea=0x401000,
        udm_tid=actual.udm_tid,
        udm=UdmModel(
            offset=96,
            size=32,
            name="__return_address",
            cmt="",
            tid=0xffffffffffffffff,
            repr="",
            effalign=0,
            tafld_bits=4096,
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
        script=textwrap.dedent(f'''
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
        '''),
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
            tid=0xffffffffffffffff,
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
        script=textwrap.dedent(f'''
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
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    matching = [e for e in event_list.root if isinstance(e, frame_udm_changed_event)]
    assert len(matching) >= 1

    actual = [e for e in matching if e.func_ea == 0x401000][-1]

    expected = frame_udm_changed_event(
        event_name="frame_udm_changed",
        timestamp=actual.timestamp,
        func_ea=0x401000,
        udm_tid=actual.udm_tid,
        udmold=UdmModel(
            offset=96,
            size=0,
            name="__return_address",
            cmt="",
            tid=0xffffffffffffffff,
            repr="",
            effalign=0,
            tafld_bits=4096,
            fda=0,
        ),
        udmnew=UdmModel(
            offset=96,
            size=0,
            name="__return_address",
            cmt="test comment for frame member",
            tid=0xffffffffffffffff,
            repr="",
            effalign=0,
            tafld_bits=4096,
            fda=0,
        ),
    )
    assert actual == expected
