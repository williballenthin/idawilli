import sys
import datetime

import ida_idaapi
import ida_idp
import ida_kernwin
import ida_segment
import ida_range
import ida_funcs
import ida_ua
import ida_gdl
import ida_moves
import ida_dirtree
import ida_typeinf


class IDBChangedHook(ida_idp.IDB_Hooks):
    def closebase(self) -> None:
        """The database will be closed now."""
        raise NotImplementedError("closebase")

    def savebase(self) -> None:
        """The database is being saved."""
        raise NotImplementedError("savebase")

    def upgraded(self, _from: int) -> None:
        """The database has been upgraded and the receiver can upgrade its info as well.
        
        Args:
            _from: Version number being upgraded from.
        """
        raise NotImplementedError("upgraded")

    def auto_empty(self) -> None:
        """Info: all analysis queues are empty.
        
        This callback is called once when the initial analysis is finished. If the queue is not empty upon the return from this callback, it will be called later again.
        """
        raise NotImplementedError("auto_empty")

    def auto_empty_finally(self) -> None:
        """Info: all analysis queues are empty definitively.
        
        This callback is called only once.
        """
        raise NotImplementedError("auto_empty_finally")

    def determined_main(self, main: ida_idaapi.ea_t) -> None:
        """The main() function has been determined.
        
        Args:
            main: Address of the main() function.
        """
        raise NotImplementedError("determined_main")

    def extlang_changed(self, kind: int, el, idx: int) -> None:
        """The list of extlangs or the default extlang was changed.
        
        Args:
            kind: 0: extlang installed, 1: extlang removed, 2: default extlang changed.
            el: Pointer to the extlang affected.
            idx: Extlang index.
        """
        raise NotImplementedError("extlang_changed")

    def idasgn_loaded(self, short_sig_name: str) -> None:
        """FLIRT signature has been loaded for normal processing.
        
        Not for recognition of startup sequences.
        
        Args:
            short_sig_name: Short signature name.
        """
        raise NotImplementedError("idasgn_loaded")

    def kernel_config_loaded(self, pass_number: int) -> None:
        """This event is issued when ida.cfg is parsed.
        
        Args:
            pass_number: Pass number.
        """
        raise NotImplementedError("kernel_config_loaded")

    def loader_finished(
        self, li, neflags: int, filetypename: str
    ) -> None:
        """External file loader finished its work.
        
        Use this event to augment the existing loader functionality.
        
        Args:
            li: Input file handle.
            neflags: Load file flags.
            filetypename: File type name.
        """
        raise NotImplementedError("loader_finished")

    def flow_chart_created(self, fc: ida_gdl.qflow_chart_t) -> None:
        """Gui has retrieved a function flow chart.
        
        Plugins may modify the flow chart in this callback.
        
        Args:
            fc: Flow chart object.
        """
        raise NotImplementedError("flow_chart_created")

    def compiler_changed(self, adjust_inf_fields: bool) -> None:
        """The kernel has changed the compiler information.
        
        Changes to idainfo::cc structure and get_abi_name.
        
        Args:
            adjust_inf_fields: May change inf fields?
        """
        raise NotImplementedError("compiler_changed")

    def changing_ti(
        self,
        ea: ida_idaapi.ea_t,
        new_type,
        new_fnames,
    ) -> None:
        """An item typestring (c/c++ prototype) is to be changed.
        
        Args:
            ea: Address.
            new_type: New type information.
            new_fnames: New field names.
        """
        raise NotImplementedError("changing_ti")

    def ti_changed(
        self, ea: ida_idaapi.ea_t, type, fnames
    ) -> None:
        """An item typestring (c/c++ prototype) has been changed.
        
        Args:
            ea: Address.
            type: Type information.
            fnames: Field names.
        """
        raise NotImplementedError("ti_changed")

    def changing_op_ti(
        self,
        ea: ida_idaapi.ea_t,
        n: int,
        new_type,
        new_fnames,
    ) -> None:
        """An operand typestring (c/c++ prototype) is to be changed.
        
        Args:
            ea: Address.
            n: Operand number.
            new_type: New type information.
            new_fnames: New field names.
        """
        raise NotImplementedError("changing_op_ti")

    def op_ti_changed(
        self,
        ea: ida_idaapi.ea_t,
        n: int,
        type,
        fnames,
    ) -> None:
        """An operand typestring (c/c++ prototype) has been changed.
        
        Args:
            ea: Address.
            n: Operand number.
            type: Type information.
            fnames: Field names.
        """
        raise NotImplementedError("op_ti_changed")

    def changing_op_type(self, ea: ida_idaapi.ea_t, n: int, opinfo) -> None:
        """An operand type (offset, hex, etc...) is to be changed.
        
        Args:
            ea: Address.
            n: Operand number, eventually or'ed with OPND_OUTER or OPND_ALL.
            opinfo: Additional operand info.
        """
        raise NotImplementedError("changing_op_type")

    def op_type_changed(self, ea: ida_idaapi.ea_t, n: int) -> None:
        """An operand type (offset, hex, etc...) has been set or deleted.
        
        Args:
            ea: Address.
            n: Operand number, eventually or'ed with OPND_OUTER or OPND_ALL.
        """
        raise NotImplementedError("op_type_changed")

    def segm_added(self, s: ida_segment.segment_t) -> None:
        """A new segment has been created.
        
        See also adding_segm.
        
        Args:
            s: Segment object.
        """
        raise NotImplementedError("segm_added")

    def deleting_segm(self, start_ea: ida_idaapi.ea_t) -> None:
        """A segment is to be deleted.
        
        Args:
            start_ea: Start address of segment.
        """
        raise NotImplementedError("deleting_segm")

    def segm_deleted(
        self, start_ea: ida_idaapi.ea_t, end_ea: ida_idaapi.ea_t, flags: int
    ) -> None:
        """A segment has been deleted.
        
        Args:
            start_ea: Start address of segment.
            end_ea: End address of segment.
            flags: Deletion flags.
        """
        raise NotImplementedError("segm_deleted")

    def changing_segm_start(
        self, s: ida_segment.segment_t, new_start: ida_idaapi.ea_t, segmod_flags: int
    ) -> None:
        """Segment start address is to be changed.
        
        Args:
            s: Segment object.
            new_start: New start address.
            segmod_flags: Segment modification flags.
        """
        raise NotImplementedError("changing_segm_start")

    def segm_start_changed(self, s: ida_segment.segment_t, oldstart: ida_idaapi.ea_t) -> None:
        """Segment start address has been changed.
        
        Args:
            s: Segment object.
            oldstart: Old start address.
        """
        raise NotImplementedError("segm_start_changed")

    def changing_segm_end(
        self, s: ida_segment.segment_t, new_end: ida_idaapi.ea_t, segmod_flags: int
    ) -> None:
        """Segment end address is to be changed.
        
        Args:
            s: Segment object.
            new_end: New end address.
            segmod_flags: Segment modification flags.
        """
        raise NotImplementedError("changing_segm_end")

    def segm_end_changed(self, s: ida_segment.segment_t, oldend: ida_idaapi.ea_t) -> None:
        """Segment end address has been changed.
        
        Args:
            s: Segment object.
            oldend: Old end address.
        """
        raise NotImplementedError("segm_end_changed")

    def changing_segm_name(self, s: ida_segment.segment_t, oldname: str) -> None:
        """Segment name is being changed.
        
        Args:
            s: Segment object.
            oldname: Old segment name.
        """
        raise NotImplementedError("changing_segm_name")

    def segm_name_changed(self, s: ida_segment.segment_t, name: str) -> None:
        """Segment name has been changed.
        
        Args:
            s: Segment object.
            name: New segment name.
        """
        raise NotImplementedError("segm_name_changed")

    def changing_segm_class(self, s: ida_segment.segment_t) -> None:
        """Segment class is being changed.
        
        Args:
            s: Segment object.
        """
        raise NotImplementedError("changing_segm_class")

    def segm_class_changed(self, s: ida_segment.segment_t, sclass: str) -> None:
        """Segment class has been changed.
        
        Args:
            s: Segment object.
            sclass: New segment class.
        """
        raise NotImplementedError("segm_class_changed")

    def segm_attrs_updated(self, s: ida_segment.segment_t) -> None:
        """Segment attributes has been changed.
        
        This event is generated for secondary segment attributes (examples: color, permissions, etc).
        
        Args:
            s: Segment object.
        """
        raise NotImplementedError("segm_attrs_updated")

    def segm_moved(
        self,
        _from: ida_idaapi.ea_t,
        to: ida_idaapi.ea_t,
        size: int,
        changed_netmap: bool,
    ) -> None:
        """Segment has been moved.
        
        See also idb_event::allsegs_moved.
        
        Args:
            _from: Source address.
            to: Destination address.
            size: Size of moved segment.
            changed_netmap: Whether netmap was changed.
        """
        raise NotImplementedError("segm_moved")

    def allsegs_moved(self, info) -> None:
        """Program rebasing is complete.
        
        This event is generated after series of segm_moved events.
        
        Args:
            info: Segment move information.
        """
        raise NotImplementedError("allsegs_moved")

    def func_added(self, pfn: ida_funcs.func_t) -> None:
        """The kernel has added a function.
        
        Args:
            pfn: Function object.
        """
        raise NotImplementedError("func_added")

    def func_updated(self, pfn: ida_funcs.func_t) -> None:
        """The kernel has updated a function.
        
        Args:
            pfn: Function object.
        """
        raise NotImplementedError("func_updated")

    def set_func_start(self, pfn: ida_funcs.func_t, new_start: ida_idaapi.ea_t) -> None:
        """Function chunk start address will be changed.
        
        Args:
            pfn: Function object.
            new_start: New start address.
        """
        raise NotImplementedError("set_func_start")

    def set_func_end(self, pfn: ida_funcs.func_t, new_end: ida_idaapi.ea_t) -> None:
        """Function chunk end address will be changed.
        
        Args:
            pfn: Function object.
            new_end: New end address.
        """
        raise NotImplementedError("set_func_end")

    def deleting_func(self, pfn: ida_funcs.func_t) -> None:
        """The kernel is about to delete a function.
        
        Args:
            pfn: Function object.
        """
        raise NotImplementedError("deleting_func")

    def frame_deleted(self, pfn: ida_funcs.func_t) -> None:
        """The kernel has deleted a function frame.
        
        See also idb_event::frame_created.
        
        Args:
            pfn: Function object.
        """
        raise NotImplementedError("frame_deleted")

    def thunk_func_created(self, pfn: ida_funcs.func_t) -> None:
        """A thunk bit has been set for a function.
        
        Args:
            pfn: Function object.
        """
        raise NotImplementedError("thunk_func_created")

    def func_tail_appended(self, pfn: ida_funcs.func_t, tail: ida_funcs.func_t) -> None:
        """A function tail chunk has been appended.
        
        Args:
            pfn: Function object.
            tail: Tail function object.
        """
        raise NotImplementedError("func_tail_appended")

    def deleting_func_tail(self, pfn: ida_funcs.func_t, tail: ida_range.range_t) -> None:
        """A function tail chunk is to be removed.
        
        Args:
            pfn: Function object.
            tail: Range of tail to be removed.
        """
        raise NotImplementedError("deleting_func_tail")

    def func_tail_deleted(self, pfn: ida_funcs.func_t, tail_ea: ida_idaapi.ea_t) -> None:
        """A function tail chunk has been removed.
        
        Args:
            pfn: Function object.
            tail_ea: Address of removed tail.
        """
        raise NotImplementedError("func_tail_deleted")

    def tail_owner_changed(
        self, tail: ida_funcs.func_t, owner_func: ida_idaapi.ea_t, old_owner: ida_idaapi.ea_t
    ) -> None:
        """A tail chunk owner has been changed.
        
        Args:
            tail: Tail function object.
            owner_func: New owner function address.
            old_owner: Old owner function address.
        """
        raise NotImplementedError("tail_owner_changed")

    def func_noret_changed(self, pfn: ida_funcs.func_t) -> None:
        """FUNC_NORET bit has been changed.
        
        Args:
            pfn: Function object.
        """
        raise NotImplementedError("func_noret_changed")

    def stkpnts_changed(self, pfn: ida_funcs.func_t) -> None:
        """Stack change points have been modified.
        
        Args:
            pfn: Function object.
        """
        raise NotImplementedError("stkpnts_changed")

    def updating_tryblks(self, tbv) -> None:
        """About to update tryblk information.
        
        Args:
            tbv: Try blocks information.
        """
        raise NotImplementedError("updating_tryblks")

    def tryblks_updated(self, tbv) -> None:
        """Updated tryblk information.
        
        Args:
            tbv: Try blocks information.
        """
        raise NotImplementedError("tryblks_updated")

    def deleting_tryblks(self, range: ida_range.range_t) -> None:
        """About to delete tryblk information in given range.
        
        Args:
            range: Range to delete tryblks from.
        """
        raise NotImplementedError("deleting_tryblks")

    def sgr_changed(
        self,
        start_ea: ida_idaapi.ea_t,
        end_ea: ida_idaapi.ea_t,
        regnum: int,
        value,
        old_value,
        tag: int,
    ) -> None:
        """The kernel has changed a segment register value.
        
        Args:
            start_ea: Start address.
            end_ea: End address.
            regnum: Register number.
            value: New register value.
            old_value: Old register value.
            tag: Segment register range tags.
        """
        raise NotImplementedError("sgr_changed")

    def make_code(self, insn: ida_ua.insn_t) -> None:
        """An instruction is being created.
        
        Args:
            insn: Instruction object.
        """
        raise NotImplementedError("make_code")

    def make_data(
        self, ea: ida_idaapi.ea_t, flags: int, tid: int, len: int
    ) -> None:
        """A data item is being created.
        
        Args:
            ea: Address.
            flags: Data flags.
            tid: Type ID.
            len: Length of data item.
        """
        raise NotImplementedError("make_data")

    def destroyed_items(
        self, ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t, will_disable_range: bool
    ) -> None:
        """Instructions/data have been destroyed in [ea1,ea2).
        
        Args:
            ea1: Start address.
            ea2: End address.
            will_disable_range: Whether range will be disabled.
        """
        raise NotImplementedError("destroyed_items")

    def renamed(
        self, ea: ida_idaapi.ea_t, new_name: str, local_name: bool, old_name: str
    ) -> None:
        """The kernel has renamed a byte.
        
        See also the rename event.
        
        Args:
            ea: Address.
            new_name: New name (can be None).
            local_name: Whether it's a local name.
            old_name: Old name (can be None).
        """
        raise NotImplementedError("renamed")

    def byte_patched(self, ea: ida_idaapi.ea_t, old_value: int) -> None:
        """A byte has been patched.
        
        Args:
            ea: Address.
            old_value: Old byte value.
        """
        raise NotImplementedError("byte_patched")

    def changing_cmt(
        self, ea: ida_idaapi.ea_t, repeatable_cmt: bool, newcmt: str
    ) -> None:
        """An item comment is to be changed.
        
        Args:
            ea: Address.
            repeatable_cmt: Whether it's a repeatable comment.
            newcmt: New comment text.
        """
        raise NotImplementedError("changing_cmt")

    def cmt_changed(self, ea: ida_idaapi.ea_t, repeatable_cmt: bool) -> None:
        """An item comment has been changed.
        
        Args:
            ea: Address.
            repeatable_cmt: Whether it's a repeatable comment.
        """
        raise NotImplementedError("cmt_changed")

    def changing_range_cmt(
        self, kind, a: ida_range.range_t, cmt: str, repeatable: bool
    ) -> None:
        """Range comment is to be changed.
        
        Args:
            kind: Range kind.
            a: Range object.
            cmt: Comment text.
            repeatable: Whether it's repeatable.
        """
        raise NotImplementedError("changing_range_cmt")

    def range_cmt_changed(
        self, kind, a: ida_range.range_t, cmt: str, repeatable: bool
    ) -> None:
        """Range comment has been changed.
        
        Args:
            kind: Range kind.
            a: Range object.
            cmt: Comment text.
            repeatable: Whether it's repeatable.
        """
        raise NotImplementedError("range_cmt_changed")

    def extra_cmt_changed(self, ea: ida_idaapi.ea_t, line_idx: int, cmt: str) -> None:
        """An extra comment has been changed.
        
        Args:
            ea: Address.
            line_idx: Line index.
            cmt: Comment text.
        """
        raise NotImplementedError("extra_cmt_changed")

    def item_color_changed(self, ea: ida_idaapi.ea_t, color) -> None:
        """An item color has been changed.
        
        If color==DEFCOLOR, then the color is deleted.
        
        Args:
            ea: Address.
            color: Background color.
        """
        raise NotImplementedError("item_color_changed")

    def callee_addr_changed(self, ea: ida_idaapi.ea_t, callee: ida_idaapi.ea_t) -> None:
        """Callee address has been updated by the user.
        
        Args:
            ea: Address.
            callee: Callee address.
        """
        raise NotImplementedError("callee_addr_changed")

    def bookmark_changed(
        self, index: int, pos: ida_moves.lochist_entry_t, desc: str, operation: int
    ) -> None:
        """Bookmarked position changed.
        
        If desc==None, then the bookmark was deleted.
        
        Args:
            index: Bookmark index.
            pos: Location history entry.
            desc: Bookmark description.
            operation: 0-added, 1-updated, 2-deleted.
        """
        raise NotImplementedError("bookmark_changed")

    def sgr_deleted(
        self, start_ea: ida_idaapi.ea_t, end_ea: ida_idaapi.ea_t, regnum: int
    ) -> None:
        """The kernel has deleted a segment register value.
        
        Args:
            start_ea: Start address.
            end_ea: End address.
            regnum: Register number.
        """
        raise NotImplementedError("sgr_deleted")

    def adding_segm(self, s: ida_segment.segment_t) -> None:
        """A segment is being created.
        
        Args:
            s: Segment object.
        """
        raise NotImplementedError("adding_segm")

    def func_deleted(self, func_ea: ida_idaapi.ea_t) -> None:
        """A function has been deleted.
        
        Args:
            func_ea: Function address.
        """
        raise NotImplementedError("func_deleted")

    def dirtree_mkdir(self, dt: ida_dirtree.dirtree_t, path: str) -> None:
        """Dirtree: a directory has been created.
        
        Args:
            dt: Directory tree object.
            path: Directory path.
        """
        raise NotImplementedError("dirtree_mkdir")

    def dirtree_rmdir(self, dt: ida_dirtree.dirtree_t, path: str) -> None:
        """Dirtree: a directory has been deleted.
        
        Args:
            dt: Directory tree object.
            path: Directory path.
        """
        raise NotImplementedError("dirtree_rmdir")

    def dirtree_link(self, dt: ida_dirtree.dirtree_t, path: str, link: bool) -> None:
        """Dirtree: an item has been linked/unlinked.
        
        Args:
            dt: Directory tree object.
            path: Item path.
            link: Whether item is being linked.
        """
        raise NotImplementedError("dirtree_link")

    def dirtree_move(self, dt: ida_dirtree.dirtree_t, _from: str, to: str) -> None:
        """Dirtree: a directory or item has been moved.
        
        Args:
            dt: Directory tree object.
            _from: Source path.
            to: Destination path.
        """
        raise NotImplementedError("dirtree_move")

    def dirtree_rank(self, dt: ida_dirtree.dirtree_t, path: str, rank: int) -> None:
        """Dirtree: a directory or item rank has been changed.
        
        Args:
            dt: Directory tree object.
            path: Item path.
            rank: New rank.
        """
        raise NotImplementedError("dirtree_rank")

    def dirtree_rminode(self, dt: ida_dirtree.dirtree_t, inode: int) -> None:
        """Dirtree: an inode became unavailable.
        
        Args:
            dt: Directory tree object.
            inode: Inode number.
        """
        raise NotImplementedError("dirtree_rminode")

    def dirtree_segm_moved(self, dt: ida_dirtree.dirtree_t) -> None:
        """Dirtree: inodes were changed due to a segment movement or a program rebasing.
        
        Args:
            dt: Directory tree object.
        """
        raise NotImplementedError("dirtree_segm_moved")

    def local_types_changed(
        self, ltc, ordinal: int, name: str
    ) -> None:
        """Local types have been changed.
        
        Args:
            ltc: Local type change information.
            ordinal: Ordinal (0 means ordinal is unknown).
            name: Type name (None means name is unknown).
        """
        raise NotImplementedError("local_types_changed")

    def lt_udm_created(self, udtname: str, udm: ida_typeinf.udm_t) -> None:
        """Local type udt member has been added.
        
        Args:
            udtname: UDT name.
            udm: UDT member object.
        """
        raise NotImplementedError("lt_udm_created")

    def lt_udm_deleted(self, udtname: str, udm_tid: int, udm: ida_typeinf.udm_t) -> None:
        """Local type udt member has been deleted.
        
        Args:
            udtname: UDT name.
            udm_tid: UDT member type ID.
            udm: UDT member object.
        """
        raise NotImplementedError("lt_udm_deleted")

    def lt_udm_renamed(self, udtname: str, udm: ida_typeinf.udm_t, oldname: str) -> None:
        """Local type udt member has been renamed.
        
        Args:
            udtname: UDT name.
            udm: UDT member object.
            oldname: Old member name.
        """
        raise NotImplementedError("lt_udm_renamed")

    def lt_udm_changed(
        self, udtname: str, udm_tid: int, udmold: ida_typeinf.udm_t, udmnew: ida_typeinf.udm_t
    ) -> None:
        """Local type udt member has been changed.
        
        Args:
            udtname: UDT name.
            udm_tid: UDT member type ID.
            udmold: Old UDT member object.
            udmnew: New UDT member object.
        """
        raise NotImplementedError("lt_udm_changed")

    def lt_udt_expanded(self, udtname: str, udm_tid: int, delta: int) -> None:
        """A structure type has been expanded/shrank.
        
        Args:
            udtname: UDT name.
            udm_tid: The gap was added/removed before this member.
            delta: Number of added/removed bytes.
        """
        raise NotImplementedError("lt_udt_expanded")

    def frame_created(self, func_ea: ida_idaapi.ea_t) -> None:
        """A function frame has been created.
        
        See also idb_event::frame_deleted.
        
        Args:
            func_ea: Function address.
        """
        raise NotImplementedError("frame_created")

    def frame_udm_created(self, func_ea: ida_idaapi.ea_t, udm: ida_typeinf.udm_t) -> None:
        """Frame member has been added.
        
        Args:
            func_ea: Function address.
            udm: UDT member object.
        """
        raise NotImplementedError("frame_udm_created")

    def frame_udm_deleted(
        self, func_ea: ida_idaapi.ea_t, udm_tid: int, udm: ida_typeinf.udm_t
    ) -> None:
        """Frame member has been deleted.
        
        Args:
            func_ea: Function address.
            udm_tid: UDT member type ID.
            udm: UDT member object.
        """
        raise NotImplementedError("frame_udm_deleted")

    def frame_udm_renamed(
        self, func_ea: ida_idaapi.ea_t, udm: ida_typeinf.udm_t, oldname: str
    ) -> None:
        """Frame member has been renamed.
        
        Args:
            func_ea: Function address.
            udm: UDT member object.
            oldname: Old member name.
        """
        raise NotImplementedError("frame_udm_renamed")

    def frame_udm_changed(
        self,
        func_ea: ida_idaapi.ea_t,
        udm_tid: int,
        udmold: ida_typeinf.udm_t,
        udmnew: ida_typeinf.udm_t,
    ) -> None:
        """Frame member has been changed.
        
        Args:
            func_ea: Function address.
            udm_tid: UDT member type ID.
            udmold: Old UDT member object.
            udmnew: New UDT member object.
        """
        raise NotImplementedError("frame_udm_changed")

    def frame_expanded(
        self, func_ea: ida_idaapi.ea_t, udm_tid: int, delta: int
    ) -> None:
        """A frame type has been expanded/shrank.
        
        Args:
            func_ea: Function address.
            udm_tid: The gap was added/removed before this member.
            delta: Number of added/removed bytes.
        """
        raise NotImplementedError("frame_expanded")

    def idasgn_matched_ea(self, ea: ida_idaapi.ea_t, name: str, lib_name: str) -> None:
        """A FLIRT match has been found.
        
        Args:
            ea: The matching address.
            name: The matched name.
            lib_name: Library name extracted from signature file.
        """
        raise NotImplementedError("idasgn_matched_ea")

    def lt_edm_created(self, enumname: str, edm: ida_typeinf.edm_t) -> None:
        """Local type enum member has been added.
        
        Args:
            enumname: Enum name.
            edm: Enum member object.
        """
        raise NotImplementedError("lt_edm_created")

    def lt_edm_deleted(self, enumname: str, edm_tid: int, edm: ida_typeinf.edm_t) -> None:
        """Local type enum member has been deleted.
        
        Args:
            enumname: Enum name.
            edm_tid: Enum member type ID.
            edm: Enum member object.
        """
        raise NotImplementedError("lt_edm_deleted")

    def lt_edm_renamed(self, enumname: str, edm: ida_typeinf.edm_t, oldname: str) -> None:
        """Local type enum member has been renamed.
        
        Args:
            enumname: Enum name.
            edm: Enum member object.
            oldname: Old member name.
        """
        raise NotImplementedError("lt_edm_renamed")

    def lt_edm_changed(
        self, enumname: str, edm_tid: int, edmold: ida_typeinf.edm_t, edmnew: ida_typeinf.edm_t
    ) -> None:
        """Local type enum member has been changed.
        
        Args:
            enumname: Enum name.
            edm_tid: Enum member type ID.
            edmold: Old enum member object.
            edmnew: New enum member object.
        """
        raise NotImplementedError("lt_edm_changed")


class ActivityLogPluginMod(ida_idaapi.plugmod_t):
    def __init__(self):
        self.idb_hooks: IDBChangedHook = None

    def run(self, arg):
        self.idb_hooks = IDBChangedHook()

        self.idb_hooks.hook()

    def term(self):
        if self.idb_hooks is not None:
            self.idb_hooks.unhook()


class ActivityLogPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    help = "Log activity in the current IDB"
    comment = ""
    wanted_name = "Activity Log"
    wanted_hotkey = ""

    def init(self):
        return ActivityLogPluginMod()


def PLUGIN_ENTRY():
    return ActivityLogPlugin()
