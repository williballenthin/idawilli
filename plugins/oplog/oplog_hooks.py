import logging
from datetime import datetime

import ida_ua
import ida_gdl
import ida_idp
import ida_name
import ida_bytes
import ida_funcs
import ida_moves
import ida_range
import ida_idaapi
import ida_dirtree
import ida_kernwin
import ida_segment
import ida_typeinf

from oplog_events import (
    Events,
    EdmModel,
    UdmModel,
    FuncModel,
    InsnModel,
    RangeModel,
    SegmentModel,
    SegmMoveInfoModel,
    renamed_event,
    make_code_event,
    make_data_event,
    func_added_event,
    segm_added_event,
    segm_moved_event,
    ti_changed_event,
    adding_segm_event,
    changing_ti_event,
    cmt_changed_event,
    sgr_changed_event,
    sgr_deleted_event,
    byte_patched_event,
    changing_cmt_event,
    dirtree_link_event,
    dirtree_move_event,
    dirtree_rank_event,
    func_deleted_event,
    func_updated_event,
    segm_deleted_event,
    set_func_end_event,
    allsegs_moved_event,
    deleting_func_event,
    deleting_segm_event,
    dirtree_mkdir_event,
    dirtree_rmdir_event,
    frame_created_event,
    frame_deleted_event,
    op_ti_changed_event,
    changing_op_ti_event,
    frame_expanded_event,
    lt_edm_changed_event,
    lt_edm_created_event,
    lt_edm_deleted_event,
    lt_edm_renamed_event,
    lt_udm_changed_event,
    lt_udm_created_event,
    lt_udm_deleted_event,
    lt_udm_renamed_event,
    set_func_start_event,
    destroyed_items_event,
    determined_main_event,
    dirtree_rminode_event,
    op_type_changed_event,
    stkpnts_changed_event,
    tryblks_updated_event,
    bookmark_changed_event,
    changing_op_type_event,
    deleting_tryblks_event,
    segm_end_changed_event,
    updating_tryblks_event,
    changing_segm_end_event,
    extra_cmt_changed_event,
    frame_udm_changed_event,
    frame_udm_created_event,
    frame_udm_deleted_event,
    frame_udm_renamed_event,
    func_tail_deleted_event,
    idasgn_matched_ea_event,
    range_cmt_changed_event,
    segm_name_changed_event,
    changing_range_cmt_event,
    changing_segm_name_event,
    deleting_func_tail_event,
    dirtree_segm_moved_event,
    func_noret_changed_event,
    func_tail_appended_event,
    item_color_changed_event,
    segm_attrs_updated_event,
    segm_class_changed_event,
    segm_start_changed_event,
    tail_owner_changed_event,
    thunk_func_created_event,
    callee_addr_changed_event,
    changing_segm_class_event,
    changing_segm_start_event,
    local_types_changed_event,
)

logger = logging.getLogger(__name__)


class IDBChangedHook(ida_idp.IDB_Hooks):
    def __init__(self, events: Events, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.events = events

    ### loading events

    def closebase(self) -> None:
        """The database will be closed now."""
        # not analytically relevant
        pass

    def savebase(self) -> None:
        """The database is being saved."""
        # not analytically relevant
        pass

    def upgraded(self, _from_version: int) -> None:
        """The database has been upgraded and the receiver can upgrade its info as well."""
        # not analytically relevant
        pass

    def auto_empty(self) -> None:
        """Info: all analysis queues are empty."""
        # not analytically relevant
        pass

    def auto_empty_finally(self) -> None:
        """Info: all analysis queues are empty definitively."""
        # not analytically relevant
        pass

    def determined_main(self, main: int) -> None:
        """The main() function has been determined."""
        logger.debug("determined_main(main=%d)", main)
        ev = determined_main_event(event_name="determined_main", timestamp=datetime.now(), main=main)
        self.events.add_event(ev)

    def extlang_changed(self, kind: int, el, idx: int) -> None:
        """The list of extlangs or the default extlang was changed.

        Args:
            kind: 0: extlang installed, 1: extlang removed, 2: default extlang changed.
            el: Pointer to the extlang affected.
            idx: Extlang index.
        """
        logger.debug("extlang_changed(kind=%d, el=%s, idx=%d)", kind, el, idx)
        pass
        # not analytically relevant if idc/idapython/whatever are enabled/disabled

    def idasgn_loaded(self, short_sig_name: str) -> None:
        """FLIRT signature has been loaded for normal processing."""
        # not analytically relevant
        pass

    def idasgn_matched_ea(self, ea: int, name: str, lib_name: str) -> None:
        """A FLIRT match has been found."""
        logger.debug("idasgn_matched_ea(ea=%d, name=%s, lib_name=%s)", ea, name, lib_name)
        ev = idasgn_matched_ea_event(
            event_name="idasgn_matched_ea", timestamp=datetime.now(), ea=ea, name=name, lib_name=lib_name
        )
        self.events.add_event(ev)

    def kernel_config_loaded(self, pass_number: int) -> None:
        """This event is issued when ida.cfg is parsed."""
        # not analytically relevant
        pass

    def loader_finished(self, li, neflags: int, filetypename: str) -> None:
        """External file loader finished its work.

        Use this event to augment the existing loader functionality.

        Args:
            li: Input file handle.
            neflags: Load file flags.
            filetypename: File type name.
        """
        # not analytically relevant
        pass

    def flow_chart_created(self, fc: ida_gdl.qflow_chart_t) -> None:
        """GUI has retrieved a function flow chart."""
        # not analytically relevant
        return

    def compiler_changed(self, adjust_inf_fields: bool) -> None:
        """The kernel has changed the compiler information."""
        # not analytically relevant
        pass

    ### segment operations

    def adding_segm(self, s: ida_segment.segment_t) -> None:
        """A segment is being created."""
        s_model = SegmentModel.from_segment_t(s)
        logger.debug("adding_segm(s=%s)", s_model.model_dump_json())
        ev = adding_segm_event(event_name="adding_segm", timestamp=datetime.now(), s=s_model)
        self.events.add_event(ev)

    def segm_added(self, s: ida_segment.segment_t) -> None:
        """A new segment has been created.

        See also adding_segm.

        Args:
            s: Segment object.
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.debug("segm_added(s=%s)", s_model.model_dump_json())
        ev = segm_added_event(event_name="segm_added", timestamp=datetime.now(), s=s_model)
        self.events.add_event(ev)

    def deleting_segm(self, start_ea: int) -> None:
        """A segment is to be deleted."""
        logger.debug("deleting_segm(start_ea=%d)", start_ea)
        ev = deleting_segm_event(event_name="deleting_segm", timestamp=datetime.now(), start_ea=start_ea)
        self.events.add_event(ev)

    def segm_deleted(self, start_ea: int, end_ea: int, flags: int) -> None:
        """A segment has been deleted."""
        logger.debug("segm_deleted(start_ea=%d, end_ea=%d, flags=%d)", start_ea, end_ea, flags)
        ev = segm_deleted_event(
            event_name="segm_deleted", timestamp=datetime.now(), start_ea=start_ea, end_ea=end_ea, flags=flags
        )
        self.events.add_event(ev)

    def changing_segm_start(self, s: ida_segment.segment_t, new_start: int, segmod_flags: int) -> None:
        """Segment start address is to be changed."""
        s_model = SegmentModel.from_segment_t(s)
        logger.debug(
            "changing_segm_start(s=%s, new_start=%d, segmod_flags=%d)",
            s_model.model_dump_json(),
            new_start,
            segmod_flags,
        )
        ev = changing_segm_start_event(
            event_name="changing_segm_start",
            timestamp=datetime.now(),
            s=s_model,
            new_start=new_start,
            segmod_flags=segmod_flags,
        )
        self.events.add_event(ev)

    def segm_start_changed(self, s: ida_segment.segment_t, oldstart: int) -> None:
        """Segment start address has been changed."""
        s_model = SegmentModel.from_segment_t(s)
        logger.debug("segm_start_changed(s=%s, oldstart=%d)", s_model.model_dump_json(), oldstart)
        ev = segm_start_changed_event(
            event_name="segm_start_changed", timestamp=datetime.now(), s=s_model, oldstart=oldstart
        )
        self.events.add_event(ev)

    def changing_segm_end(self, s: ida_segment.segment_t, new_end: int, segmod_flags: int) -> None:
        """Segment end address is to be changed."""
        s_model = SegmentModel.from_segment_t(s)
        logger.debug(
            "changing_segm_end(s=%s, new_end=%d, segmod_flags=%d)",
            s_model.model_dump_json(),
            new_end,
            segmod_flags,
        )
        ev = changing_segm_end_event(
            event_name="changing_segm_end",
            timestamp=datetime.now(),
            s=s_model,
            new_end=new_end,
            segmod_flags=segmod_flags,
        )
        self.events.add_event(ev)

    def segm_end_changed(self, s: ida_segment.segment_t, oldend: int) -> None:
        """Segment end address has been changed."""
        s_model = SegmentModel.from_segment_t(s)
        logger.debug("segm_end_changed(s=%s, oldend=%d)", s_model.model_dump_json(), oldend)
        ev = segm_end_changed_event(event_name="segm_end_changed", timestamp=datetime.now(), s=s_model, oldend=oldend)
        self.events.add_event(ev)

    def changing_segm_name(self, s: ida_segment.segment_t, oldname: str) -> None:
        """Segment name is being changed.

        s.name == oldname

        See also segm_name_changed, which has the new name.
        There's not an event with both old and new names.
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.debug("changing_segm_name(s=%s, oldname=%s)", s_model.model_dump_json(), oldname)
        ev = changing_segm_name_event(
            event_name="changing_segm_name", timestamp=datetime.now(), s=s_model, oldname=oldname
        )
        self.events.add_event(ev)

    def segm_name_changed(self, s: ida_segment.segment_t, name: str) -> None:
        """Segment name has been changed.

        s.name == name (new name)

        See also changing_segm_name, which has the old name.
        There's not an event with both old and new names.
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.debug("segm_name_changed(s=%s, name=%s)", s_model.model_dump_json(), name)
        ev = segm_name_changed_event(event_name="segm_name_changed", timestamp=datetime.now(), s=s_model, name=name)
        self.events.add_event(ev)

    def changing_segm_class(self, s: ida_segment.segment_t) -> None:
        """Segment class is being changed."""
        s_model = SegmentModel.from_segment_t(s)
        logger.debug("changing_segm_class(s=%s)", s_model.model_dump_json())
        ev = changing_segm_class_event(event_name="changing_segm_class", timestamp=datetime.now(), s=s_model)
        self.events.add_event(ev)

    def segm_class_changed(self, s: ida_segment.segment_t, sclass: str) -> None:
        """Segment class has been changed."""
        s_model = SegmentModel.from_segment_t(s)
        logger.debug("segm_class_changed(s=%s, sclass=%s)", s_model.model_dump_json(), sclass)
        ev = segm_class_changed_event(
            event_name="segm_class_changed", timestamp=datetime.now(), s=s_model, sclass=sclass
        )
        self.events.add_event(ev)

    def segm_attrs_updated(self, s: ida_segment.segment_t) -> None:
        """Segment attributes has been changed.

        This event is generated for secondary segment attributes (examples: color, permissions, etc).
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.debug("segm_attrs_updated(s=%s)", s_model.model_dump_json())
        ev = segm_attrs_updated_event(event_name="segm_attrs_updated", timestamp=datetime.now(), s=s_model)
        self.events.add_event(ev)

    def segm_moved(
        self,
        _from: int,
        to: int,
        size: int,
        changed_netmap: bool,
    ) -> None:
        """Segment has been moved.

        See also idb_event::allsegs_moved.
        """
        logger.debug(
            "segm_moved(_from=%d, to=%d, size=%d, changed_netmap=%s)",
            _from,
            to,
            size,
            changed_netmap,
        )
        ev = segm_moved_event(
            event_name="segm_moved",
            timestamp=datetime.now(),
            _from=_from,
            to=to,
            size=size,
            changed_netmap=changed_netmap,
        )
        self.events.add_event(ev)

    def allsegs_moved(self, info: ida_moves.segm_move_infos_t) -> None:
        """Program rebasing is complete.

        This event is generated after series of segm_moved events.

        Args:
            info: Segment move information (segm_move_infos_t).
        """
        logger.debug("allsegs_moved(info=%s)", info)
        moves = [SegmMoveInfoModel.from_segm_move_info_t(info[i]) for i in range(len(info))]
        ev = allsegs_moved_event(event_name="allsegs_moved", timestamp=datetime.now(), moves=moves)
        self.events.add_event(ev)

    ### function operations

    def func_added(self, pfn: ida_funcs.func_t) -> None:
        """The kernel has added a function."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.debug("func_added(pfn=%s)", pfn_model.model_dump_json())
        ev = func_added_event(event_name="func_added", timestamp=datetime.now(), pfn=pfn_model)
        self.events.add_event(ev)

    def func_updated(self, pfn: ida_funcs.func_t) -> None:
        """The kernel has updated a function."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.debug("func_updated(pfn=%s)", pfn_model.model_dump_json())
        ev = func_updated_event(event_name="func_updated", timestamp=datetime.now(), pfn=pfn_model)
        self.events.add_event(ev)

    def set_func_start(self, pfn: ida_funcs.func_t, new_start: int) -> None:
        """Function chunk start address will be changed."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.debug("set_func_start(pfn=%s, new_start=%d)", pfn_model.model_dump_json(), new_start)
        ev = set_func_start_event(
            event_name="set_func_start", timestamp=datetime.now(), pfn=pfn_model, new_start=new_start
        )
        self.events.add_event(ev)

    def set_func_end(self, pfn: ida_funcs.func_t, new_end: int) -> None:
        """Function chunk end address will be changed."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.debug("set_func_end(pfn=%s, new_end=%d)", pfn_model.model_dump_json(), new_end)
        ev = set_func_end_event(event_name="set_func_end", timestamp=datetime.now(), pfn=pfn_model, new_end=new_end)
        self.events.add_event(ev)

    def deleting_func(self, pfn: ida_funcs.func_t) -> None:
        """The kernel is about to delete a function."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.debug("deleting_func(pfn=%s)", pfn_model.model_dump_json())
        ev = deleting_func_event(event_name="deleting_func", timestamp=datetime.now(), pfn=pfn_model)
        self.events.add_event(ev)

    def func_deleted(self, func_ea: int) -> None:
        """A function has been deleted."""
        logger.debug("func_deleted(func_ea=%d)", func_ea)
        ev = func_deleted_event(event_name="func_deleted", timestamp=datetime.now(), func_ea=func_ea)
        self.events.add_event(ev)

    def thunk_func_created(self, pfn: ida_funcs.func_t) -> None:
        """A thunk bit has been set for a function."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.debug("thunk_func_created(pfn=%s)", pfn_model.model_dump_json())
        ev = thunk_func_created_event(event_name="thunk_func_created", timestamp=datetime.now(), pfn=pfn_model)
        self.events.add_event(ev)

    def func_tail_appended(self, pfn: ida_funcs.func_t, tail: ida_funcs.func_t) -> None:
        """A function tail chunk has been appended."""
        pfn_model = FuncModel.from_func_t(pfn)
        tail_model = FuncModel.from_func_t(tail)
        logger.debug("func_tail_appended(pfn=%s, tail=%s)", pfn_model.model_dump_json(), tail_model.model_dump_json())
        ev = func_tail_appended_event(
            event_name="func_tail_appended", timestamp=datetime.now(), pfn=pfn_model, tail=tail_model
        )
        self.events.add_event(ev)

    def deleting_func_tail(self, pfn: ida_funcs.func_t, tail: ida_range.range_t) -> None:
        """A function tail chunk is to be removed."""
        pfn_model = FuncModel.from_func_t(pfn)
        tail_model = RangeModel.from_range_t(tail)
        logger.debug("deleting_func_tail(pfn=%s, tail=%s)", pfn_model.model_dump_json(), tail_model.model_dump_json())
        ev = deleting_func_tail_event(
            event_name="deleting_func_tail", timestamp=datetime.now(), pfn=pfn_model, tail=tail_model
        )
        self.events.add_event(ev)

    def func_tail_deleted(self, pfn: ida_funcs.func_t, tail_ea: int) -> None:
        """A function tail chunk has been removed."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.debug("func_tail_deleted(pfn=%s, tail_ea=%d)", pfn_model.model_dump_json(), tail_ea)
        ev = func_tail_deleted_event(
            event_name="func_tail_deleted", timestamp=datetime.now(), pfn=pfn_model, tail_ea=tail_ea
        )
        self.events.add_event(ev)

    def tail_owner_changed(
        self,
        tail: ida_funcs.func_t,
        owner_func: int,
        old_owner: int,
    ) -> None:
        """A tail chunk owner has been changed."""
        tail_model = FuncModel.from_func_t(tail)
        logger.debug(
            "tail_owner_changed(tail=%s, owner_func=%d, old_owner=%d)",
            tail_model.model_dump_json(),
            owner_func,
            old_owner,
        )
        ev = tail_owner_changed_event(
            event_name="tail_owner_changed",
            timestamp=datetime.now(),
            tail=tail_model,
            owner_func=owner_func,
            old_owner=old_owner,
        )
        self.events.add_event(ev)

    def func_noret_changed(self, pfn: ida_funcs.func_t) -> None:
        """FUNC_NORET bit has been changed."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.debug("func_noret_changed(pfn=%s)", pfn_model.model_dump_json())
        ev = func_noret_changed_event(event_name="func_noret_changed", timestamp=datetime.now(), pfn=pfn_model)
        self.events.add_event(ev)

    # TODO: type of tbv
    def updating_tryblks(self, tbv) -> None:
        """About to update tryblk information."""
        logger.debug("updating_tryblks(tbv=%s)", tbv)
        ev = updating_tryblks_event(event_name="updating_tryblks", timestamp=datetime.now(), tbv=tbv)
        self.events.add_event(ev)

    def tryblks_updated(self, tbv) -> None:
        """Updated tryblk information."""
        logger.debug("tryblks_updated(tbv=%s)", tbv)
        ev = tryblks_updated_event(event_name="tryblks_updated", timestamp=datetime.now(), tbv=tbv)
        self.events.add_event(ev)

    def deleting_tryblks(self, range: ida_range.range_t) -> None:
        """About to delete tryblk information in given range."""
        range_model = RangeModel.from_range_t(range)
        logger.debug("deleting_tryblks(range=%s)", range_model.model_dump_json())
        ev = deleting_tryblks_event(event_name="deleting_tryblks", timestamp=datetime.now(), range=range_model)
        self.events.add_event(ev)

    ### comments

    def changing_cmt(self, ea: int, repeatable_cmt: bool, newcmt: str) -> None:
        """An item comment is to be changed."""
        logger.debug(
            "changing_cmt(ea=%d, repeatable_cmt=%s, newcmt=%s)",
            ea,
            repeatable_cmt,
            newcmt,
        )
        ev = changing_cmt_event(
            event_name="changing_cmt", timestamp=datetime.now(), ea=ea, repeatable_cmt=repeatable_cmt, newcmt=newcmt
        )
        self.events.add_event(ev)

    def cmt_changed(self, ea: int, repeatable_cmt: bool) -> None:
        """An item comment has been changed."""
        logger.debug("cmt_changed(ea=%d, repeatable_cmt=%s)", ea, repeatable_cmt)
        ev = cmt_changed_event(event_name="cmt_changed", timestamp=datetime.now(), ea=ea, repeatable_cmt=repeatable_cmt)
        self.events.add_event(ev)

    def changing_range_cmt(self, kind, a: ida_range.range_t, cmt: str, repeatable: bool) -> None:
        """Range comment is to be changed."""
        a_model = RangeModel.from_range_t(a)
        logger.debug(
            "changing_range_cmt(kind=%s, a=%s, cmt=%s, repeatable=%s)",
            kind,
            a_model.model_dump_json(),
            cmt,
            repeatable,
        )
        ev = changing_range_cmt_event(
            event_name="changing_range_cmt",
            timestamp=datetime.now(),
            kind=kind,
            a=a_model,
            cmt=cmt,
            repeatable=repeatable,
        )
        self.events.add_event(ev)

    # TODO: what is a range comment???
    def range_cmt_changed(self, kind, a: ida_range.range_t, cmt: str, repeatable: bool) -> None:
        """Range comment has been changed."""
        a_model = RangeModel.from_range_t(a)
        logger.debug(
            "range_cmt_changed(kind=%s, a=%s, cmt=%s, repeatable=%s)",
            kind,
            a_model.model_dump_json(),
            cmt,
            repeatable,
        )
        ev = range_cmt_changed_event(
            event_name="range_cmt_changed",
            timestamp=datetime.now(),
            kind=kind,
            a=a_model,
            cmt=cmt,
            repeatable=repeatable,
        )
        self.events.add_event(ev)

    def extra_cmt_changed(self, ea: int, line_idx: int, cmt: str) -> None:
        """An extra comment has been changed."""
        logger.debug("extra_cmt_changed(ea=%d, line_idx=%d, cmt=%s)", ea, line_idx, cmt)
        ev = extra_cmt_changed_event(
            event_name="extra_cmt_changed", timestamp=datetime.now(), ea=ea, line_idx=line_idx, cmt=cmt
        )
        self.events.add_event(ev)

    ### item operations

    def sgr_changed(
        self,
        start_ea: int,
        end_ea: int,
        regnum: int,
        value,
        old_value,
        tag: int,
    ) -> None:
        """The kernel has changed a segment register value."""
        logger.debug(
            "sgr_changed(start_ea=%d, end_ea=%d, regnum=%d, value=%s, old_value=%s, tag=%d)",
            start_ea,
            end_ea,
            regnum,
            value,
            old_value,
            tag,
        )
        ev = sgr_changed_event(
            event_name="sgr_changed",
            timestamp=datetime.now(),
            start_ea=start_ea,
            end_ea=end_ea,
            regnum=regnum,
            value=value,
            old_value=old_value,
            tag=tag,
        )
        self.events.add_event(ev)

    def sgr_deleted(self, start_ea: int, end_ea: int, regnum: int) -> None:
        """The kernel has deleted a segment register value."""
        logger.debug("sgr_deleted(start_ea=%d, end_ea=%d, regnum=%d)", start_ea, end_ea, regnum)
        ev = sgr_deleted_event(
            event_name="sgr_deleted", timestamp=datetime.now(), start_ea=start_ea, end_ea=end_ea, regnum=regnum
        )
        self.events.add_event(ev)

    def make_code(self, insn: ida_ua.insn_t) -> None:
        """An instruction is being created."""
        insn_model = InsnModel.from_insn_t(insn)
        logger.debug("make_code(insn=%s)", insn_model.model_dump_json())
        ev = make_code_event(event_name="make_code", timestamp=datetime.now(), insn=insn_model)
        self.events.add_event(ev)

    def make_data(self, ea: int, flags: int, tid: int, len: int) -> None:
        """A data item is being created."""
        logger.debug("make_data(ea=%d, flags=%d, tid=%d, len=%d)", ea, flags, tid, len)
        ev = make_data_event(event_name="make_data", timestamp=datetime.now(), ea=ea, flags=flags, tid=tid, len=len)
        self.events.add_event(ev)

    def destroyed_items(self, ea1: int, ea2: int, will_disable_range: bool) -> None:
        """Instructions/data have been destroyed in [ea1,ea2)."""
        logger.debug(
            "destroyed_items(ea1=%d, ea2=%d, will_disable_range=%s)",
            ea1,
            ea2,
            will_disable_range,
        )
        ev = destroyed_items_event(
            event_name="destroyed_items",
            timestamp=datetime.now(),
            ea1=ea1,
            ea2=ea2,
            will_disable_range=will_disable_range,
        )
        self.events.add_event(ev)

    def renamed(self, ea: int, new_name: str, local_name: bool, old_name: str) -> None:
        """The kernel has renamed a byte.

        See also the rename event."""
        logger.debug(
            "renamed(ea=%d, new_name=%s, local_name=%s, old_name=%s)",
            ea,
            new_name,
            local_name,
            old_name,
        )
        ev = renamed_event(
            event_name="renamed",
            timestamp=datetime.now(),
            ea=ea,
            new_name=new_name,
            local_name=local_name,
            old_name=old_name,
        )
        self.events.add_event(ev)

    def byte_patched(self, ea: int, old_value: int) -> None:
        """A byte has been patched."""
        logger.debug("byte_patched(ea=%d, old_value=%d)", ea, old_value)
        ev = byte_patched_event(event_name="byte_patched", timestamp=datetime.now(), ea=ea, old_value=old_value)
        self.events.add_event(ev)

    def item_color_changed(self, ea: int, color) -> None:
        """An item color has been changed.

        If color==DEFCOLOR, then the color is deleted."""
        logger.debug("item_color_changed(ea=%d, color=%s)", ea, color)
        ev = item_color_changed_event(event_name="item_color_changed", timestamp=datetime.now(), ea=ea, color=color)
        self.events.add_event(ev)

    def callee_addr_changed(self, ea: int, callee: int) -> None:
        """Callee address has been updated by the user."""
        logger.debug("callee_addr_changed(ea=%d, callee=%d)", ea, callee)
        ev = callee_addr_changed_event(event_name="callee_addr_changed", timestamp=datetime.now(), ea=ea, callee=callee)
        self.events.add_event(ev)

    def bookmark_changed(self, index: int, pos: ida_moves.lochist_entry_t, desc: str, operation: int) -> None:
        """Bookmarked position changed.

        If desc==None, then the bookmark was deleted."""
        # TODO: this can fail
        ea = pos.place().toea()
        logger.debug(
            "bookmark_changed(index=%d, ea=%d, desc=%s, operation=%d)",
            index,
            ea,
            desc,
            operation,
        )
        ev = bookmark_changed_event(
            event_name="bookmark_changed", timestamp=datetime.now(), index=index, ea=ea, desc=desc, operation=operation
        )
        self.events.add_event(ev)

    # TODO: what is opinfo? type?
    # https://python.docs.hex-rays.com/ida_nalt/index.html#ida_nalt.opinfo_t
    # this has more info than op_type_changed
    def changing_op_type(self, ea: int, n: int, opinfo) -> None:
        """An operand type (offset, hex, etc...) is to be changed."""
        logger.debug("changing_op_type(ea=%d, n=%d, opinfo=%s)", ea, n, opinfo)
        # TODO: opinfo cannot be serialized
        ev = changing_op_type_event(event_name="changing_op_type", timestamp=datetime.now(), ea=ea, n=n)
        self.events.add_event(ev)

    def op_type_changed(self, ea: int, n: int) -> None:
        """An operand type (offset, hex, etc...) has been set or deleted.

        Args:
            ea: Address.
            n: Operand number, eventually or'ed with OPND_OUTER or OPND_ALL.
        """
        logger.debug("op_type_changed(ea=%d, n=%d)", ea, n)
        ev = op_type_changed_event(event_name="op_type_changed", timestamp=datetime.now(), ea=ea, n=n)
        self.events.add_event(ev)

    ### dirtree

    # TODO: figure out how to get the dirtree type (bookmarks/functions/etc.)
    def dirtree_mkdir(self, dt: ida_dirtree.dirtree_t, path: str) -> None:
        """Dirtree: a directory has been created."""
        logger.debug("dirtree_mkdir(path=%s)", path)
        ev = dirtree_mkdir_event(event_name="dirtree_mkdir", timestamp=datetime.now(), path=path)
        self.events.add_event(ev)

    def dirtree_rmdir(self, dt: ida_dirtree.dirtree_t, path: str) -> None:
        """Dirtree: a directory has been deleted."""
        logger.debug("dirtree_rmdir(path=%s)", path)
        ev = dirtree_rmdir_event(event_name="dirtree_rmdir", timestamp=datetime.now(), path=path)
        self.events.add_event(ev)

    def dirtree_link(self, dt: ida_dirtree.dirtree_t, path: str, link: bool) -> None:
        """Dirtree: an item has been linked/unlinked."""
        logger.debug("dirtree_link(path=%s, link=%s)", path, link)
        ev = dirtree_link_event(event_name="dirtree_link", timestamp=datetime.now(), path=path, link=link)
        self.events.add_event(ev)

    def dirtree_move(self, dt: ida_dirtree.dirtree_t, _from: str, to: str) -> None:
        """Dirtree: a directory or item has been moved."""
        logger.debug("dirtree_move(_from=%s, to=%s)", _from, to)
        ev = dirtree_move_event(event_name="dirtree_move", timestamp=datetime.now(), _from=_from, to=to)
        self.events.add_event(ev)

    def dirtree_rank(self, dt: ida_dirtree.dirtree_t, path: str, rank: int) -> None:
        """Dirtree: a directory or item rank has been changed."""
        logger.debug("dirtree_rank(path=%s, rank=%d)", path, rank)
        ev = dirtree_rank_event(event_name="dirtree_rank", timestamp=datetime.now(), path=path, rank=rank)
        self.events.add_event(ev)

    def dirtree_rminode(self, dt: ida_dirtree.dirtree_t, inode: int) -> None:
        """Dirtree: an inode became unavailable."""
        logger.debug("dirtree_rminode(inode=%d)", inode)
        ev = dirtree_rminode_event(event_name="dirtree_rminode", timestamp=datetime.now(), inode=inode)
        self.events.add_event(ev)

    def dirtree_segm_moved(self, dt: ida_dirtree.dirtree_t) -> None:
        """Dirtree: inodes were changed due to a segment movement or a program rebasing."""
        logger.debug("dirtree_segm_moved()")
        ev = dirtree_segm_moved_event(event_name="dirtree_segm_moved", timestamp=datetime.now())
        self.events.add_event(ev)

    ### types

    def changing_ti(
        self,
        ea: int,
        new_type: bytes,
        new_fnames: bytes,
    ) -> None:
        """An item typestring (C/C++ prototype) is to be changed."""
        logger.debug("changing_ti(ea=%d, new_type=%s, new_fnames=%s)", ea, new_type, new_fnames)
        ev = changing_ti_event(
            event_name="changing_ti", timestamp=datetime.now(), ea=ea, new_type=new_type, new_fnames=new_fnames
        )
        self.events.add_event(ev)

    def ti_changed(self, ea: int, type: bytes, fnames: bytes) -> None:
        """An item typestring (C/C++ prototype) has been changed."""
        logger.debug("ti_changed(ea=%d, type=%s, fnames=%s)", ea, type, fnames)
        ev = ti_changed_event(event_name="ti_changed", timestamp=datetime.now(), ea=ea, type=type, fnames=fnames)
        self.events.add_event(ev)

    def changing_op_ti(
        self,
        ea: int,
        n: int,
        new_type: bytes,
        new_fnames: bytes,
    ) -> None:
        """An operand typestring (c/c++ prototype) is to be changed."""
        logger.debug(
            "changing_op_ti(ea=%d, n=%d, new_type=%s, new_fnames=%s)",
            ea,
            n,
            new_type,
            new_fnames,
        )
        ev = changing_op_ti_event(
            event_name="changing_op_ti", timestamp=datetime.now(), ea=ea, n=n, new_type=new_type, new_fnames=new_fnames
        )
        self.events.add_event(ev)

    def op_ti_changed(
        self,
        ea: int,
        n: int,
        type: bytes,
        fnames: bytes,
    ) -> None:
        """An operand typestring (c/c++ prototype) has been changed."""
        logger.debug("op_ti_changed(ea=%d, n=%d, type=%s, fnames=%s)", ea, n, type, fnames)
        ev = op_ti_changed_event(
            event_name="op_ti_changed", timestamp=datetime.now(), ea=ea, n=n, type=type, fnames=fnames
        )
        self.events.add_event(ev)

    ### local types

    def local_types_changed(self, ltc, ordinal: int, name: str) -> None:
        """Local types have been changed.

        Args:
            ltc (local_type_change_t):
            ordinal: 0 means ordinal is unknown
            name: nullptr means name is unknown
        """
        logger.debug("local_types_changed(ltc=%s, ordinal=%d, name=%s)", ltc, ordinal, name)
        ev = local_types_changed_event(
            event_name="local_types_changed", timestamp=datetime.now(), ltc=ltc, ordinal=ordinal, name=name
        )
        self.events.add_event(ev)

    def lt_udm_created(self, udtname: str, udm: ida_typeinf.udm_t) -> None:
        """Local type udt member has been added."""
        udm_model = UdmModel.from_udm_t(udm)
        logger.debug("lt_udm_created(udtname=%s, udm=%s)", udtname, udm_model.model_dump_json())
        ev = lt_udm_created_event(event_name="lt_udm_created", timestamp=datetime.now(), udtname=udtname, udm=udm_model)
        self.events.add_event(ev)

    def lt_udm_deleted(self, udtname: str, udm_tid: int, udm: ida_typeinf.udm_t) -> None:
        """Local type udt member has been deleted."""
        udm_model = UdmModel.from_udm_t(udm)
        logger.debug("lt_udm_deleted(udtname=%s, udm_tid=%d, udm=%s)", udtname, udm_tid, udm_model.model_dump_json())
        ev = lt_udm_deleted_event(
            event_name="lt_udm_deleted", timestamp=datetime.now(), udtname=udtname, udm_tid=udm_tid, udm=udm_model
        )
        self.events.add_event(ev)

    def lt_udm_renamed(self, udtname: str, udm: ida_typeinf.udm_t, oldname: str) -> None:
        """Local type udt member has been renamed."""
        udm_model = UdmModel.from_udm_t(udm)
        logger.debug("lt_udm_renamed(udtname=%s, udm=%s, oldname=%s)", udtname, udm_model.model_dump_json(), oldname)
        ev = lt_udm_renamed_event(
            event_name="lt_udm_renamed", timestamp=datetime.now(), udtname=udtname, udm=udm_model, oldname=oldname
        )
        self.events.add_event(ev)

    def lt_udm_changed(
        self,
        udtname: str,
        udm_tid: int,
        udmold: ida_typeinf.udm_t,
        udmnew: ida_typeinf.udm_t,
    ) -> None:
        """Local type udt member has been changed."""
        udmold_model = UdmModel.from_udm_t(udmold)
        udmnew_model = UdmModel.from_udm_t(udmnew)
        logger.debug(
            "lt_udm_changed(udtname=%s, udm_tid=%d, udmold=%s, udmnew=%s)",
            udtname,
            udm_tid,
            udmold_model.model_dump_json(),
            udmnew_model.model_dump_json(),
        )
        ev = lt_udm_changed_event(
            event_name="lt_udm_changed",
            timestamp=datetime.now(),
            udtname=udtname,
            udm_tid=udm_tid,
            udmold=udmold_model,
            udmnew=udmnew_model,
        )
        self.events.add_event(ev)

    def lt_udt_expanded(self, udtname: str, udm_tid: int, delta: int) -> None:
        """A structure type has been expanded/shrank.

        Args:
            udm_tid: The gap was added/removed before this member.
            delta: Number of added/removed bytes.
        """
        logger.debug("lt_udt_expanded(udtname=%s, udm_tid=%d, delta=%d)", udtname, udm_tid, delta)
        ev = lt_udt_expanded_event(
            event_name="lt_udt_expanded", timestamp=datetime.now(), udtname=udtname, udm_tid=udm_tid, delta=delta
        )
        self.events.add_event(ev)

    def lt_edm_created(self, enumname: str, edm: ida_typeinf.edm_t) -> None:
        """Local type enum member has been added."""
        edm_model = EdmModel.from_edm_t(edm)
        logger.debug("lt_edm_created(enumname=%s, edm=%s)", enumname, edm_model.model_dump_json())
        ev = lt_edm_created_event(
            event_name="lt_edm_created", timestamp=datetime.now(), enumname=enumname, edm=edm_model
        )
        self.events.add_event(ev)

    def lt_edm_deleted(self, enumname: str, edm_tid: int, edm: ida_typeinf.edm_t) -> None:
        """Local type enum member has been deleted."""
        edm_model = EdmModel.from_edm_t(edm)
        logger.debug("lt_edm_deleted(enumname=%s, edm_tid=%d, edm=%s)", enumname, edm_tid, edm_model.model_dump_json())
        ev = lt_edm_deleted_event(
            event_name="lt_edm_deleted", timestamp=datetime.now(), enumname=enumname, edm_tid=edm_tid, edm=edm_model
        )
        self.events.add_event(ev)

    def lt_edm_renamed(self, enumname: str, edm: ida_typeinf.edm_t, oldname: str) -> None:
        """Local type enum member has been renamed."""
        edm_model = EdmModel.from_edm_t(edm)
        logger.debug("lt_edm_renamed(enumname=%s, edm=%s, oldname=%s)", enumname, edm_model.model_dump_json(), oldname)
        ev = lt_edm_renamed_event(
            event_name="lt_edm_renamed", timestamp=datetime.now(), enumname=enumname, edm=edm_model, oldname=oldname
        )
        self.events.add_event(ev)

    def lt_edm_changed(
        self,
        enumname: str,
        edm_tid: int,
        edmold: ida_typeinf.edm_t,
        edmnew: ida_typeinf.edm_t,
    ) -> None:
        """Local type enum member has been changed."""
        edmold_model = EdmModel.from_edm_t(edmold)
        edmnew_model = EdmModel.from_edm_t(edmnew)
        logger.debug(
            "lt_edm_changed(enumname=%s, edm_tid=%d, edmold=%s, edmnew=%s)",
            enumname,
            edm_tid,
            edmold_model.model_dump_json(),
            edmnew_model.model_dump_json(),
        )
        ev = lt_edm_changed_event(
            event_name="lt_edm_changed",
            timestamp=datetime.now(),
            enumname=enumname,
            edm_tid=edm_tid,
            edmold=edmold_model,
            edmnew=edmnew_model,
        )
        self.events.add_event(ev)

    ### frames

    def stkpnts_changed(self, pfn: ida_funcs.func_t) -> None:
        """Stack change points have been modified."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.debug("stkpnts_changed(pfn=%s)", pfn_model.model_dump_json())
        ev = stkpnts_changed_event(event_name="stkpnts_changed", timestamp=datetime.now(), pfn=pfn_model)
        self.events.add_event(ev)

    def frame_created(self, func_ea: int) -> None:
        """A function frame has been created.

        See also idb_event::frame_deleted.
        """
        logger.debug("frame_created(func_ea=%d)", func_ea)
        ev = frame_created_event(event_name="frame_created", timestamp=datetime.now(), func_ea=func_ea)
        self.events.add_event(ev)

    def frame_expanded(self, func_ea: int, udm_tid: int, delta: int) -> None:
        """A frame type has been expanded/shrank.

        Args:
            udm_tid: The gap was added/removed before this member.
            delta: Number of added/removed bytes.
        """
        logger.debug("frame_expanded(func_ea=%d, udm_tid=%d, delta=%d)", func_ea, udm_tid, delta)
        ev = frame_expanded_event(
            event_name="frame_expanded", timestamp=datetime.now(), func_ea=func_ea, udm_tid=udm_tid, delta=delta
        )
        self.events.add_event(ev)

    def frame_deleted(self, pfn: ida_funcs.func_t) -> None:
        """The kernel has deleted a function frame.

        See also idb_event::frame_created.
        """
        pfn_model = FuncModel.from_func_t(pfn)
        logger.debug("frame_deleted(pfn=%s)", pfn_model.model_dump_json())
        ev = frame_deleted_event(event_name="frame_deleted", timestamp=datetime.now(), pfn=pfn_model)
        self.events.add_event(ev)

    def frame_udm_created(self, func_ea: int, udm: ida_typeinf.udm_t) -> None:
        """Frame member has been added."""
        udm_model = UdmModel.from_udm_t(udm)
        logger.debug("frame_udm_created(func_ea=%d, udm=%s)", func_ea, udm_model.model_dump_json())
        ev = frame_udm_created_event(
            event_name="frame_udm_created", timestamp=datetime.now(), func_ea=func_ea, udm=udm_model
        )
        self.events.add_event(ev)

    def frame_udm_deleted(self, func_ea: int, udm_tid: int, udm: ida_typeinf.udm_t) -> None:
        """Frame member has been deleted."""
        udm_model = UdmModel.from_udm_t(udm)
        logger.debug("frame_udm_deleted(func_ea=%d, udm_tid=%d, udm=%s)", func_ea, udm_tid, udm_model.model_dump_json())
        ev = frame_udm_deleted_event(
            event_name="frame_udm_deleted", timestamp=datetime.now(), func_ea=func_ea, udm_tid=udm_tid, udm=udm_model
        )
        self.events.add_event(ev)

    def frame_udm_renamed(self, func_ea: int, udm: ida_typeinf.udm_t, oldname: str) -> None:
        """Frame member has been renamed."""
        udm_model = UdmModel.from_udm_t(udm)
        logger.debug("frame_udm_renamed(func_ea=%d, udm=%s, oldname=%s)", func_ea, udm_model.model_dump_json(), oldname)
        ev = frame_udm_renamed_event(
            event_name="frame_udm_renamed", timestamp=datetime.now(), func_ea=func_ea, udm=udm_model, oldname=oldname
        )
        self.events.add_event(ev)

    def frame_udm_changed(
        self,
        func_ea: int,
        udm_tid: int,
        udmold: ida_typeinf.udm_t,
        udmnew: ida_typeinf.udm_t,
    ) -> None:
        """Frame member has been changed."""
        udmold_model = UdmModel.from_udm_t(udmold)
        udmnew_model = UdmModel.from_udm_t(udmnew)
        logger.debug(
            "frame_udm_changed(func_ea=%d, udm_tid=%d, udmold=%s, udmnew=%s)",
            func_ea,
            udm_tid,
            udmold_model.model_dump_json(),
            udmnew_model.model_dump_json(),
        )
        ev = frame_udm_changed_event(
            event_name="frame_udm_changed",
            timestamp=datetime.now(),
            func_ea=func_ea,
            udm_tid=udm_tid,
            udmold=udmold_model,
            udmnew=udmnew_model,
        )
        self.events.add_event(ev)
