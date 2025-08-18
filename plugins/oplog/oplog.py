import logging
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator

import ida_ua
import ida_gdl
import ida_idp
import ida_funcs
import ida_moves
import ida_range
import ida_idaapi
import ida_dirtree
import ida_segment
import ida_typeinf

logger = logging.getLogger(__name__)


class FuncModel(BaseModel):
    """Pydantic model for ida_funcs.func_t structure."""

    start_ea: int
    end_ea: int
    flags: int
    frame: int
    frsize: int
    frregs: int
    argsize: int
    fpd: int
    color: int
    pntqty: int
    regvarqty: int
    regargqty: int
    tailqty: int
    owner: int
    refqty: int
    name: str | None = None

    @classmethod
    def from_func_t(cls, func: ida_funcs.func_t) -> "FuncModel":
        """Create FuncModel from ida_funcs.func_t instance."""
        return cls(
            start_ea=func.start_ea,
            end_ea=func.end_ea,
            flags=func.flags,
            frame=func.frame,
            frsize=func.frsize,
            frregs=func.frregs,
            argsize=func.argsize,
            fpd=func.fpd,
            color=func.color,
            pntqty=func.pntqty,
            regvarqty=func.regvarqty,
            regargqty=func.regargqty,
            tailqty=func.tailqty,
            owner=func.owner,
            refqty=func.refqty,
            name=func.get_name() if hasattr(func, "get_name") else None,
        )


Func = ida_funcs.func_t | FuncModel


class OpModel(BaseModel):
    """Pydantic model for ida_ua.op_t structure."""

    n: int
    type: int
    offb: int
    offo: int
    flags: int
    dtype: int
    reg: int
    phrase: int
    value: int
    addr: int
    specval: int
    specflag1: int
    specflag2: int
    specflag3: int
    specflag4: int

    @classmethod
    def from_op_t(cls, op: ida_ua.op_t) -> "OpModel":
        """Create OpModel from ida_ua.op_t instance."""
        return cls(
            n=op.n,
            type=op.type,
            offb=op.offb,
            offo=op.offo,
            flags=op.flags,
            dtype=op.dtype,
            reg=op.reg,
            phrase=op.phrase,
            value=op.value,
            addr=op.addr,
            specval=op.specval,
            specflag1=op.specflag1,
            specflag2=op.specflag2,
            specflag3=op.specflag3,
            specflag4=op.specflag4,
        )


Op = ida_ua.op_t | OpModel


class InsnModel(BaseModel):
    """Pydantic model for ida_ua.insn_t structure."""

    cs: int
    ip: int
    ea: int
    itype: int
    size: int
    auxpref: int
    auxpref_u16: list[int]
    auxpref_u8: list[int]
    segpref: int
    insnpref: int
    flags: int
    ops: list[OpModel]

    @classmethod
    def from_insn_t(cls, insn: ida_ua.insn_t) -> "InsnModel":
        """Create InsnModel from ida_ua.insn_t instance."""
        return cls(
            cs=insn.cs,
            ip=insn.ip,
            ea=insn.ea,
            itype=insn.itype,
            size=insn.size,
            auxpref=insn.auxpref,
            auxpref_u16=list(insn.auxpref_u16),
            auxpref_u8=list(insn.auxpref_u8),
            segpref=insn.segpref,
            insnpref=insn.insnpref,
            flags=insn.flags,
            ops=[OpModel.from_op_t(insn.ops[i]) for i in range(8)],
        )


Insn = ida_ua.insn_t | InsnModel


class SegmentModel(BaseModel):
    """Pydantic model for ida_segment.segment_t structure."""

    start_ea: int
    end_ea: int
    name: int
    sclass: int
    orgbase: int
    align: int
    comb: int
    perm: int
    bitness: int
    flags: int
    sel: int
    defsr: list[int]
    type: int
    color: int
    segment_name: str | None = None
    segment_class: str | None = None

    @field_validator("bitness")
    @classmethod
    def validate_bitness(cls, v: int) -> int:
        """Validate bitness is in range 0-2."""
        if v not in (0, 1, 2):
            raise ValueError("bitness must be 0 (16bit), 1 (32bit), or 2 (64bit)")
        return v

    @field_validator("defsr")
    @classmethod
    def validate_defsr_length(cls, v: list[int]) -> list[int]:
        """Validate defsr list has exactly 16 elements."""
        if len(v) != 16:
            raise ValueError(f"defsr must have exactly 16 elements, got {len(v)}")
        return v

    @field_validator("align")
    @classmethod
    def validate_align(cls, v: int) -> int:
        """Validate align is in range 0-255."""
        if not (0 <= v <= 255):
            raise ValueError(f"align must be in range 0-255, got {v}")
        return v

    @field_validator("comb")
    @classmethod
    def validate_comb(cls, v: int) -> int:
        """Validate comb is in range 0-255."""
        if not (0 <= v <= 255):
            raise ValueError(f"comb must be in range 0-255, got {v}")
        return v

    @field_validator("perm")
    @classmethod
    def validate_perm(cls, v: int) -> int:
        """Validate perm is in range 0-255."""
        if not (0 <= v <= 255):
            raise ValueError(f"perm must be in range 0-255, got {v}")
        return v

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: int) -> int:
        """Validate type is in range 0-255."""
        if not (0 <= v <= 255):
            raise ValueError(f"type must be in range 0-255, got {v}")
        return v

    @field_validator("flags")
    @classmethod
    def validate_flags(cls, v: int) -> int:
        """Validate flags is in range 0-65535."""
        if not (0 <= v <= 65535):
            raise ValueError(f"flags must be in range 0-65535, got {v}")
        return v

    @classmethod
    def from_segment_t(cls, segment: ida_segment.segment_t) -> "SegmentModel":
        """Create SegmentModel from ida_segment.segment_t instance."""
        # Convert defsr array to list
        defsr_list = [segment.defsr[i] for i in range(16)]

        return cls(
            start_ea=segment.start_ea,
            end_ea=segment.end_ea,
            name=segment.name,
            sclass=segment.sclass,
            orgbase=segment.orgbase,
            align=segment.align,
            comb=segment.comb,
            perm=segment.perm,
            bitness=segment.bitness,
            flags=segment.flags,
            sel=segment.sel,
            defsr=defsr_list,
            type=segment.type,
            color=segment.color,
            segment_name=ida_segment.get_segm_name(segment) if segment else None,
            segment_class=ida_segment.get_segm_class(segment) if segment else None,
        )


Segment = ida_segment.segment_t | SegmentModel


class RangeModel(BaseModel):
    """Pydantic model for ida_range.range_t structure."""

    start_ea: int
    end_ea: int

    @classmethod
    def from_range_t(cls, range_obj: ida_range.range_t) -> "RangeModel":
        """Create RangeModel from ida_range.range_t instance.

        Args:
            range_obj: The range_t instance to convert.

        Returns:
            RangeModel instance with populated attributes.
        """
        return cls(
            start_ea=range_obj.start_ea,
            end_ea=range_obj.end_ea,
        )


Range = ida_range.range_t | RangeModel


class UdmModel(BaseModel):
    """Pydantic model for ida_typeinf.udm_t structure."""

    offset: int
    size: int
    name: str
    cmt: str
    tid: str  # from udm.type.get_tid()
    repr: str
    effalign: int
    tafld_bits: int
    fda: int

    @classmethod
    def from_udm_t(cls, udm: ida_typeinf.udm_t) -> "UdmModel":
        return cls(
            offset=udm.offset,
            size=udm.size,
            name=udm.name,
            cmt=udm.cmt,
            tid=udm.type.get_tid(),
            repr=str(udm.repr),
            effalign=udm.effalign,
            tafld_bits=udm.tafld_bits,
            fda=udm.fda,
        )


Udm = ida_typeinf.udm_t | UdmModel


class EdmModel(BaseModel):
    """Pydantic model for ida_typeinf.edm_t structure."""

    name: str
    comment: str
    value: int
    tid: int

    @classmethod
    def from_edm_t(cls, edm: ida_typeinf.edm_t) -> "EdmModel":
        name = edm.name
        comment = edm.cmt
        value = edm.value
        tid = edm.get_tid()

        return cls(
            name=name,
            comment=comment,
            value=value,
            tid=tid,
        )


Edm = ida_typeinf.edm_t | EdmModel


class adding_segm_event(BaseModel):
    event_name: Literal["adding_segm"]
    s: SegmentModel


class segm_added_event(BaseModel):
    event_name: Literal["segm_added"]
    s: SegmentModel


class deleting_segm_event(BaseModel):
    event_name: Literal["deleting_segm"]
    start_ea: int


class segm_deleted_event(BaseModel):
    event_name: Literal["segm_deleted"]
    start_ea: int
    end_ea: int
    flags: int


class changing_segm_start_event(BaseModel):
    event_name: Literal["changing_segm_start"]
    s: SegmentModel
    new_start: int
    segmod_flags: int


class segm_start_changed_event(BaseModel):
    event_name: Literal["segm_start_changed"]
    s: SegmentModel
    oldstart: int


class changing_segm_end_event(BaseModel):
    event_name: Literal["changing_segm_end"]
    s: SegmentModel
    new_end: int
    segmod_flags: int


class segm_end_changed_event(BaseModel):
    event_name: Literal["segm_end_changed"]
    s: SegmentModel
    oldend: int


class changing_segm_name_event(BaseModel):
    event_name: Literal["changing_segm_name"]
    s: SegmentModel
    oldname: str


class segm_name_changed_event(BaseModel):
    event_name: Literal["segm_name_changed"]
    s: SegmentModel
    name: str


class changing_segm_class_event(BaseModel):
    event_name: Literal["changing_segm_class"]
    s: SegmentModel


class segm_class_changed_event(BaseModel):
    event_name: Literal["segm_class_changed"]
    s: SegmentModel
    sclass: str


class segm_attrs_updated_event(BaseModel):
    event_name: Literal["segm_attrs_updated"]
    s: SegmentModel


class segm_moved_event(BaseModel):
    event_name: Literal["segm_moved"]
    _from: int
    to: int
    size: int
    changed_netmap: bool


class allsegs_moved_event(BaseModel):
    event_name: Literal["allsegs_moved"]
    info: Any


class func_added_event(BaseModel):
    event_name: Literal["func_added"]
    pfn: FuncModel


class func_updated_event(BaseModel):
    event_name: Literal["func_updated"]
    pfn: FuncModel


class set_func_start_event(BaseModel):
    event_name: Literal["set_func_start"]
    pfn: FuncModel
    new_start: int


class set_func_end_event(BaseModel):
    event_name: Literal["set_func_end"]
    pfn: FuncModel
    new_end: int


class deleting_func_event(BaseModel):
    event_name: Literal["deleting_func"]
    pfn: FuncModel


class func_deleted_event(BaseModel):
    event_name: Literal["func_deleted"]
    func_ea: int


class thunk_func_created_event(BaseModel):
    event_name: Literal["thunk_func_created"]
    pfn: FuncModel


class func_tail_appended_event(BaseModel):
    event_name: Literal["func_tail_appended"]
    pfn: FuncModel
    tail: FuncModel


class deleting_func_tail_event(BaseModel):
    event_name: Literal["deleting_func_tail"]
    pfn: FuncModel
    tail: RangeModel


class func_tail_deleted_event(BaseModel):
    event_name: Literal["func_tail_deleted"]
    pfn: FuncModel
    tail_ea: int


class tail_owner_changed_event(BaseModel):
    event_name: Literal["tail_owner_changed"]
    tail: FuncModel
    owner_func: int
    old_owner: int


class func_noret_changed_event(BaseModel):
    event_name: Literal["func_noret_changed"]
    pfn: FuncModel


class updating_tryblks_event(BaseModel):
    event_name: Literal["updating_tryblks"]
    tbv: Any


class tryblks_updated_event(BaseModel):
    event_name: Literal["tryblks_updated"]
    tbv: Any


class deleting_tryblks_event(BaseModel):
    event_name: Literal["deleting_tryblks"]
    range: RangeModel


class changing_cmt_event(BaseModel):
    event_name: Literal["changing_cmt"]
    ea: int
    repeatable_cmt: bool
    newcmt: str


class cmt_changed_event(BaseModel):
    event_name: Literal["cmt_changed"]
    ea: int
    repeatable_cmt: bool


class changing_range_cmt_event(BaseModel):
    event_name: Literal["changing_range_cmt"]
    kind: Any
    a: RangeModel
    cmt: str
    repeatable: bool


class range_cmt_changed_event(BaseModel):
    event_name: Literal["range_cmt_changed"]
    kind: Any
    a: RangeModel
    cmt: str
    repeatable: bool


class extra_cmt_changed_event(BaseModel):
    event_name: Literal["extra_cmt_changed"]
    ea: int
    line_idx: int
    cmt: str


class sgr_changed_event(BaseModel):
    event_name: Literal["sgr_changed"]
    start_ea: int
    end_ea: int
    regnum: int
    value: Any
    old_value: Any
    tag: int


class sgr_deleted_event(BaseModel):
    event_name: Literal["sgr_deleted"]
    start_ea: int
    end_ea: int
    regnum: int


class make_code_event(BaseModel):
    event_name: Literal["make_code"]
    insn: InsnModel


class make_data_event(BaseModel):
    event_name: Literal["make_data"]
    ea: int
    flags: int
    tid: int
    len: int


class destroyed_items_event(BaseModel):
    event_name: Literal["destroyed_items"]
    ea1: int
    ea2: int
    will_disable_range: bool


class renamed_event(BaseModel):
    event_name: Literal["renamed"]
    ea: int
    new_name: str
    local_name: bool
    old_name: str


class byte_patched_event(BaseModel):
    event_name: Literal["byte_patched"]
    ea: int
    old_value: int


class item_color_changed_event(BaseModel):
    event_name: Literal["item_color_changed"]
    ea: int
    color: Any


class callee_addr_changed_event(BaseModel):
    event_name: Literal["callee_addr_changed"]
    ea: int
    callee: int


class bookmark_changed_event(BaseModel):
    event_name: Literal["bookmark_changed"]
    index: int
    ea: int
    desc: str
    operation: int


class changing_op_type_event(BaseModel):
    event_name: Literal["changing_op_type"]
    ea: int
    n: int
    opinfo: Any


class op_type_changed_event(BaseModel):
    event_name: Literal["op_type_changed"]
    ea: int
    n: int


class dirtree_mkdir_event(BaseModel):
    event_name: Literal["dirtree_mkdir"]
    path: str


class dirtree_rmdir_event(BaseModel):
    event_name: Literal["dirtree_rmdir"]
    path: str


class dirtree_link_event(BaseModel):
    event_name: Literal["dirtree_link"]
    path: str
    link: bool


class dirtree_move_event(BaseModel):
    event_name: Literal["dirtree_move"]
    _from: str
    to: str


class dirtree_rank_event(BaseModel):
    event_name: Literal["dirtree_rank"]
    path: str
    rank: int


class dirtree_rminode_event(BaseModel):
    event_name: Literal["dirtree_rminode"]
    inode: int


class dirtree_segm_moved_event(BaseModel):
    event_name: Literal["dirtree_segm_moved"]


class changing_ti_event(BaseModel):
    event_name: Literal["changing_ti"]
    ea: int
    new_type: Any
    new_fnames: Any


class ti_changed_event(BaseModel):
    event_name: Literal["ti_changed"]
    ea: int
    type: Any
    fnames: Any


class changing_op_ti_event(BaseModel):
    event_name: Literal["changing_op_ti"]
    ea: int
    n: int
    new_type: Any
    new_fnames: Any


class op_ti_changed_event(BaseModel):
    event_name: Literal["op_ti_changed"]
    ea: int
    n: int
    type: Any
    fnames: Any


class local_types_changed_event(BaseModel):
    event_name: Literal["local_types_changed"]
    ltc: Any
    ordinal: int
    name: str


class lt_udm_created_event(BaseModel):
    event_name: Literal["lt_udm_created"]
    udtname: str
    udm: UdmModel


class lt_udm_deleted_event(BaseModel):
    event_name: Literal["lt_udm_deleted"]
    udtname: str
    udm_tid: int
    udm: UdmModel


class lt_udm_renamed_event(BaseModel):
    event_name: Literal["lt_udm_renamed"]
    udtname: str
    udm: UdmModel
    oldname: str


class lt_udm_changed_event(BaseModel):
    event_name: Literal["lt_udm_changed"]
    udtname: str
    udm_tid: int
    udmold: UdmModel
    udmnew: UdmModel


class lt_udt_expanded_event(BaseModel):
    event_name: Literal["lt_udt_expanded"]
    udtname: str
    udm_tid: int
    delta: int


class lt_edm_created_event(BaseModel):
    event_name: Literal["lt_edm_created"]
    enumname: str
    edm: EdmModel


class lt_edm_deleted_event(BaseModel):
    event_name: Literal["lt_edm_deleted"]
    enumname: str
    edm_tid: int
    edm: EdmModel


class lt_edm_renamed_event(BaseModel):
    event_name: Literal["lt_edm_renamed"]
    enumname: str
    edm: EdmModel
    oldname: str


class lt_edm_changed_event(BaseModel):
    event_name: Literal["lt_edm_changed"]
    enumname: str
    edm_tid: int
    edmold: EdmModel
    edmnew: EdmModel


class stkpnts_changed_event(BaseModel):
    event_name: Literal["stkpnts_changed"]
    pfn: FuncModel


class frame_created_event(BaseModel):
    event_name: Literal["frame_created"]
    func_ea: int


class frame_expanded_event(BaseModel):
    event_name: Literal["frame_expanded"]
    func_ea: int
    udm_tid: int
    delta: int


class frame_deleted_event(BaseModel):
    event_name: Literal["frame_deleted"]
    pfn: FuncModel


class frame_udm_created_event(BaseModel):
    event_name: Literal["frame_udm_created"]
    func_ea: int
    udm: UdmModel


class frame_udm_deleted_event(BaseModel):
    event_name: Literal["frame_udm_deleted"]
    func_ea: int
    udm_tid: int
    udm: UdmModel


class frame_udm_renamed_event(BaseModel):
    event_name: Literal["frame_udm_renamed"]
    func_ea: int
    udm: UdmModel
    oldname: str


class frame_udm_changed_event(BaseModel):
    event_name: Literal["frame_udm_changed"]
    func_ea: int
    udm_tid: int
    udmold: UdmModel
    udmnew: UdmModel


def cb(ev: Any):
    print(ev)


class IDBChangedHook(ida_idp.IDB_Hooks):

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

    def determined_main(self, main: ida_idaapi.ea_t) -> None:
        """The main() function has been determined."""
        logger.info("determined_main(main=%d)", main)
        ev = determined_main_event(event_name="determined_main", main=main)
        cb(ev)

    def extlang_changed(self, kind: int, el, idx: int) -> None:
        """The list of extlangs or the default extlang was changed.

        Args:
            kind: 0: extlang installed, 1: extlang removed, 2: default extlang changed.
            el: Pointer to the extlang affected.
            idx: Extlang index.
        """
        logger.info("extlang_changed(kind=%d, el=%s, idx=%d)", kind, el, idx)
        ev = extlang_changed_event(event_name="extlang_changed", kind=kind, el=el, idx=idx)
        cb(ev)

    def idasgn_loaded(self, short_sig_name: str) -> None:
        """FLIRT signature has been loaded for normal processing."""
        # not analytically relevant
        pass

    def idasgn_matched_ea(self, ea: ida_idaapi.ea_t, name: str, lib_name: str) -> None:
        """A FLIRT match has been found."""
        logger.info("idasgn_matched_ea(ea=%d, name=%s, lib_name=%s)", ea, name, lib_name)
        ev = idasgn_matched_ea_event(event_name="idasgn_matched_ea", ea=ea, name=name, lib_name=lib_name)
        cb(ev)

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
        logger.info("adding_segm(s=%s)", s_model.model_dump_json())
        ev = adding_segm_event(event_name="adding_segm", s=s_model)
        cb(ev)

    def segm_added(self, s: ida_segment.segment_t) -> None:
        """A new segment has been created.

        See also adding_segm.

        Args:
            s: Segment object.
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.info("segm_added(s=%s)", s_model.model_dump_json())
        ev = segm_added_event(event_name="segm_added", s=s_model)
        cb(ev)

    def deleting_segm(self, start_ea: ida_idaapi.ea_t) -> None:
        """A segment is to be deleted."""
        logger.info("deleting_segm(start_ea=%d)", start_ea)
        ev = deleting_segm_event(event_name="deleting_segm", start_ea=start_ea)
        cb(ev)

    def segm_deleted(self, start_ea: ida_idaapi.ea_t, end_ea: ida_idaapi.ea_t, flags: int) -> None:
        """A segment has been deleted."""
        logger.info("segm_deleted(start_ea=%d, end_ea=%d, flags=%d)", start_ea, end_ea, flags)
        ev = segm_deleted_event(event_name="segm_deleted", start_ea=start_ea, end_ea=end_ea, flags=flags)
        cb(ev)

    def changing_segm_start(self, s: ida_segment.segment_t, new_start: ida_idaapi.ea_t, segmod_flags: int) -> None:
        """Segment start address is to be changed."""
        s_model = SegmentModel.from_segment_t(s)
        logger.info(
            "changing_segm_start(s=%s, new_start=%d, segmod_flags=%d)",
            s_model.model_dump_json(),
            new_start,
            segmod_flags,
        )
        ev = changing_segm_start_event(
            event_name="changing_segm_start", s=s_model, new_start=new_start, segmod_flags=segmod_flags
        )
        cb(ev)

    def segm_start_changed(self, s: ida_segment.segment_t, oldstart: ida_idaapi.ea_t) -> None:
        """Segment start address has been changed."""
        s_model = SegmentModel.from_segment_t(s)
        logger.info("segm_start_changed(s=%s, oldstart=%d)", s_model.model_dump_json(), oldstart)
        ev = segm_start_changed_event(event_name="segm_start_changed", s=s_model, oldstart=oldstart)
        cb(ev)

    def changing_segm_end(self, s: ida_segment.segment_t, new_end: ida_idaapi.ea_t, segmod_flags: int) -> None:
        """Segment end address is to be changed."""
        s_model = SegmentModel.from_segment_t(s)
        logger.info(
            "changing_segm_end(s=%s, new_end=%d, segmod_flags=%d)",
            s_model.model_dump_json(),
            new_end,
            segmod_flags,
        )
        ev = changing_segm_end_event(
            event_name="changing_segm_end", s=s_model, new_end=new_end, segmod_flags=segmod_flags
        )
        cb(ev)

    def segm_end_changed(self, s: ida_segment.segment_t, oldend: ida_idaapi.ea_t) -> None:
        """Segment end address has been changed."""
        s_model = SegmentModel.from_segment_t(s)
        logger.info("segm_end_changed(s=%s, oldend=%d)", s_model.model_dump_json(), oldend)
        ev = segm_end_changed_event(event_name="segm_end_changed", s=s_model, oldend=oldend)
        cb(ev)

    def changing_segm_name(self, s: ida_segment.segment_t, oldname: str) -> None:
        """Segment name is being changed.

        s.name == oldname

        See also segm_name_changed, which has the new name.
        There's not an event with both old and new names.
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.info("changing_segm_name(s=%s, oldname=%s)", s_model.model_dump_json(), oldname)
        ev = changing_segm_name_event(event_name="changing_segm_name", s=s_model, oldname=oldname)
        cb(ev)

    def segm_name_changed(self, s: ida_segment.segment_t, name: str) -> None:
        """Segment name has been changed.

        s.name == name (new name)

        See also changing_segm_name, which has the old name.
        There's not an event with both old and new names.
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.info("segm_name_changed(s=%s, name=%s)", s_model.model_dump_json(), name)
        ev = segm_name_changed_event(event_name="segm_name_changed", s=s_model, name=name)
        cb(ev)

    def changing_segm_class(self, s: ida_segment.segment_t) -> None:
        """Segment class is being changed."""
        s_model = SegmentModel.from_segment_t(s)
        logger.info("changing_segm_class(s=%s)", s_model.model_dump_json())
        ev = changing_segm_class_event(event_name="changing_segm_class", s=s_model)
        cb(ev)

    def segm_class_changed(self, s: ida_segment.segment_t, sclass: str) -> None:
        """Segment class has been changed."""
        s_model = SegmentModel.from_segment_t(s)
        logger.info("segm_class_changed(s=%s, sclass=%s)", s_model.model_dump_json(), sclass)
        ev = segm_class_changed_event(event_name="segm_class_changed", s=s_model, sclass=sclass)
        cb(ev)

    def segm_attrs_updated(self, s: ida_segment.segment_t) -> None:
        """Segment attributes has been changed.

        This event is generated for secondary segment attributes (examples: color, permissions, etc).
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.info("segm_attrs_updated(s=%s)", s_model.model_dump_json())
        ev = segm_attrs_updated_event(event_name="segm_attrs_updated", s=s_model)
        cb(ev)

    def segm_moved(
        self,
        _from: ida_idaapi.ea_t,
        to: ida_idaapi.ea_t,
        size: int,
        changed_netmap: bool,
    ) -> None:
        """Segment has been moved.

        See also idb_event::allsegs_moved.
        """
        logger.info(
            "segm_moved(_from=%d, to=%d, size=%d, changed_netmap=%s)",
            _from,
            to,
            size,
            changed_netmap,
        )
        ev = segm_moved_event(event_name="segm_moved", _from=_from, to=to, size=size, changed_netmap=changed_netmap)
        cb(ev)

    # TODO: type of info
    def allsegs_moved(self, info) -> None:
        """Program rebasing is complete.

        This event is generated after series of segm_moved events.

        Args:
            info: Segment move information.
        """
        logger.info("allsegs_moved(info=%s)", info)
        ev = allsegs_moved_event(event_name="allsegs_moved", info=info)
        cb(ev)

    ### function operations

    def func_added(self, pfn: ida_funcs.func_t) -> None:
        """The kernel has added a function."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.info("func_added(pfn=%s)", pfn_model.model_dump_json())
        ev = func_added_event(event_name="func_added", pfn=pfn_model)
        cb(ev)

    def func_updated(self, pfn: ida_funcs.func_t) -> None:
        """The kernel has updated a function."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.info("func_updated(pfn=%s)", pfn_model.model_dump_json())
        ev = func_updated_event(event_name="func_updated", pfn=pfn_model)
        cb(ev)

    def set_func_start(self, pfn: ida_funcs.func_t, new_start: ida_idaapi.ea_t) -> None:
        """Function chunk start address will be changed."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.info("set_func_start(pfn=%s, new_start=%d)", pfn_model.model_dump_json(), new_start)
        ev = set_func_start_event(event_name="set_func_start", pfn=pfn_model, new_start=new_start)
        cb(ev)

    def set_func_end(self, pfn: ida_funcs.func_t, new_end: ida_idaapi.ea_t) -> None:
        """Function chunk end address will be changed."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.info("set_func_end(pfn=%s, new_end=%d)", pfn_model.model_dump_json(), new_end)
        ev = set_func_end_event(event_name="set_func_end", pfn=pfn_model, new_end=new_end)
        cb(ev)

    def deleting_func(self, pfn: ida_funcs.func_t) -> None:
        """The kernel is about to delete a function."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.info("deleting_func(pfn=%s)", pfn_model.model_dump_json())
        ev = deleting_func_event(event_name="deleting_func", pfn=pfn_model)
        cb(ev)

    def func_deleted(self, func_ea: ida_idaapi.ea_t) -> None:
        """A function has been deleted."""
        logger.info("func_deleted(func_ea=%d)", func_ea)
        ev = func_deleted_event(event_name="func_deleted", func_ea=func_ea)
        cb(ev)

    def thunk_func_created(self, pfn: ida_funcs.func_t) -> None:
        """A thunk bit has been set for a function."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.info("thunk_func_created(pfn=%s)", pfn_model.model_dump_json())
        ev = thunk_func_created_event(event_name="thunk_func_created", pfn=pfn_model)
        cb(ev)

    def func_tail_appended(self, pfn: ida_funcs.func_t, tail: ida_funcs.func_t) -> None:
        """A function tail chunk has been appended."""
        pfn_model = FuncModel.from_func_t(pfn)
        tail_model = FuncModel.from_func_t(tail)
        logger.info("func_tail_appended(pfn=%s, tail=%s)", pfn_model.model_dump_json(), tail_model.model_dump_json())
        ev = func_tail_appended_event(event_name="func_tail_appended", pfn=pfn_model, tail=tail_model)
        cb(ev)

    def deleting_func_tail(self, pfn: ida_funcs.func_t, tail: ida_range.range_t) -> None:
        """A function tail chunk is to be removed."""
        pfn_model = FuncModel.from_func_t(pfn)
        tail_model = RangeModel.from_range_t(tail)
        logger.info("deleting_func_tail(pfn=%s, tail=%s)", pfn_model.model_dump_json(), tail_model.model_dump_json())
        ev = deleting_func_tail_event(event_name="deleting_func_tail", pfn=pfn_model, tail=tail_model)
        cb(ev)

    def func_tail_deleted(self, pfn: ida_funcs.func_t, tail_ea: ida_idaapi.ea_t) -> None:
        """A function tail chunk has been removed."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.info("func_tail_deleted(pfn=%s, tail_ea=%d)", pfn_model.model_dump_json(), tail_ea)
        ev = func_tail_deleted_event(event_name="func_tail_deleted", pfn=pfn_model, tail_ea=tail_ea)
        cb(ev)

    def tail_owner_changed(
        self,
        tail: ida_funcs.func_t,
        owner_func: ida_idaapi.ea_t,
        old_owner: ida_idaapi.ea_t,
    ) -> None:
        """A tail chunk owner has been changed."""
        tail_model = FuncModel.from_func_t(tail)
        logger.info(
            "tail_owner_changed(tail=%s, owner_func=%d, old_owner=%d)",
            tail_model.model_dump_json(),
            owner_func,
            old_owner,
        )
        ev = tail_owner_changed_event(
            event_name="tail_owner_changed", tail=tail_model, owner_func=owner_func, old_owner=old_owner
        )
        cb(ev)

    def func_noret_changed(self, pfn: ida_funcs.func_t) -> None:
        """FUNC_NORET bit has been changed."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.info("func_noret_changed(pfn=%s)", pfn_model.model_dump_json())
        ev = func_noret_changed_event(event_name="func_noret_changed", pfn=pfn_model)
        cb(ev)

    # TODO: type of tbv
    def updating_tryblks(self, tbv) -> None:
        """About to update tryblk information."""
        logger.info("updating_tryblks(tbv=%s)", tbv)
        ev = updating_tryblks_event(event_name="updating_tryblks", tbv=tbv)
        cb(ev)

    def tryblks_updated(self, tbv) -> None:
        """Updated tryblk information."""
        logger.info("tryblks_updated(tbv=%s)", tbv)
        ev = tryblks_updated_event(event_name="tryblks_updated", tbv=tbv)
        cb(ev)

    def deleting_tryblks(self, range: ida_range.range_t) -> None:
        """About to delete tryblk information in given range."""
        range_model = RangeModel.from_range_t(range)
        logger.info("deleting_tryblks(range=%s)", range_model.model_dump_json())
        ev = deleting_tryblks_event(event_name="deleting_tryblks", range=range_model)
        cb(ev)

    ### comments

    def changing_cmt(self, ea: ida_idaapi.ea_t, repeatable_cmt: bool, newcmt: str) -> None:
        """An item comment is to be changed."""
        logger.info(
            "changing_cmt(ea=%d, repeatable_cmt=%s, newcmt=%s)",
            ea,
            repeatable_cmt,
            newcmt,
        )
        ev = changing_cmt_event(event_name="changing_cmt", ea=ea, repeatable_cmt=repeatable_cmt, newcmt=newcmt)
        cb(ev)

    def cmt_changed(self, ea: ida_idaapi.ea_t, repeatable_cmt: bool) -> None:
        """An item comment has been changed."""
        logger.info("cmt_changed(ea=%d, repeatable_cmt=%s)", ea, repeatable_cmt)
        ev = cmt_changed_event(event_name="cmt_changed", ea=ea, repeatable_cmt=repeatable_cmt)
        cb(ev)

    def changing_range_cmt(self, kind, a: ida_range.range_t, cmt: str, repeatable: bool) -> None:
        """Range comment is to be changed."""
        a_model = RangeModel.from_range_t(a)
        logger.info(
            "changing_range_cmt(kind=%s, a=%s, cmt=%s, repeatable=%s)",
            kind,
            a_model.model_dump_json(),
            cmt,
            repeatable,
        )
        ev = changing_range_cmt_event(
            event_name="changing_range_cmt", kind=kind, a=a_model, cmt=cmt, repeatable=repeatable
        )
        cb(ev)

    # TODO: what is a range comment???
    def range_cmt_changed(self, kind, a: ida_range.range_t, cmt: str, repeatable: bool) -> None:
        """Range comment has been changed."""
        a_model = RangeModel.from_range_t(a)
        logger.info(
            "range_cmt_changed(kind=%s, a=%s, cmt=%s, repeatable=%s)",
            kind,
            a_model.model_dump_json(),
            cmt,
            repeatable,
        )
        ev = range_cmt_changed_event(
            event_name="range_cmt_changed", kind=kind, a=a_model, cmt=cmt, repeatable=repeatable
        )
        cb(ev)

    def extra_cmt_changed(self, ea: ida_idaapi.ea_t, line_idx: int, cmt: str) -> None:
        """An extra comment has been changed."""
        logger.info("extra_cmt_changed(ea=%d, line_idx=%d, cmt=%s)", ea, line_idx, cmt)
        ev = extra_cmt_changed_event(event_name="extra_cmt_changed", ea=ea, line_idx=line_idx, cmt=cmt)
        cb(ev)

    ### item operations

    def sgr_changed(
        self,
        start_ea: ida_idaapi.ea_t,
        end_ea: ida_idaapi.ea_t,
        regnum: int,
        value,
        old_value,
        tag: int,
    ) -> None:
        """The kernel has changed a segment register value."""
        logger.info(
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
            start_ea=start_ea,
            end_ea=end_ea,
            regnum=regnum,
            value=value,
            old_value=old_value,
            tag=tag,
        )
        cb(ev)

    def sgr_deleted(self, start_ea: ida_idaapi.ea_t, end_ea: ida_idaapi.ea_t, regnum: int) -> None:
        """The kernel has deleted a segment register value."""
        logger.info("sgr_deleted(start_ea=%d, end_ea=%d, regnum=%d)", start_ea, end_ea, regnum)
        ev = sgr_deleted_event(event_name="sgr_deleted", start_ea=start_ea, end_ea=end_ea, regnum=regnum)
        cb(ev)

    def make_code(self, insn: ida_ua.insn_t) -> None:
        """An instruction is being created."""
        insn_model = InsnModel.from_insn_t(insn)
        logger.info("make_code(insn=%s)", insn_model.model_dump_json())
        ev = make_code_event(event_name="make_code", insn=insn_model)
        cb(ev)

    def make_data(self, ea: ida_idaapi.ea_t, flags: int, tid: int, len: int) -> None:
        """A data item is being created."""
        logger.info("make_data(ea=%d, flags=%d, tid=%d, len=%d)", ea, flags, tid, len)
        ev = make_data_event(event_name="make_data", ea=ea, flags=flags, tid=tid, len=len)
        cb(ev)

    def destroyed_items(self, ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t, will_disable_range: bool) -> None:
        """Instructions/data have been destroyed in [ea1,ea2)."""
        logger.info(
            "destroyed_items(ea1=%d, ea2=%d, will_disable_range=%s)",
            ea1,
            ea2,
            will_disable_range,
        )
        ev = destroyed_items_event(
            event_name="destroyed_items", ea1=ea1, ea2=ea2, will_disable_range=will_disable_range
        )
        cb(ev)

    def renamed(self, ea: ida_idaapi.ea_t, new_name: str, local_name: bool, old_name: str) -> None:
        """The kernel has renamed a byte.

        See also the rename event."""
        logger.info(
            "renamed(ea=%d, new_name=%s, local_name=%s, old_name=%s)",
            ea,
            new_name,
            local_name,
            old_name,
        )
        ev = renamed_event(event_name="renamed", ea=ea, new_name=new_name, local_name=local_name, old_name=old_name)
        cb(ev)

    def byte_patched(self, ea: ida_idaapi.ea_t, old_value: int) -> None:
        """A byte has been patched."""
        logger.info("byte_patched(ea=%d, old_value=%d)", ea, old_value)
        ev = byte_patched_event(event_name="byte_patched", ea=ea, old_value=old_value)
        cb(ev)

    def item_color_changed(self, ea: ida_idaapi.ea_t, color) -> None:
        """An item color has been changed.

        If color==DEFCOLOR, then the color is deleted."""
        logger.info("item_color_changed(ea=%d, color=%s)", ea, color)
        ev = item_color_changed_event(event_name="item_color_changed", ea=ea, color=color)
        cb(ev)

    def callee_addr_changed(self, ea: ida_idaapi.ea_t, callee: ida_idaapi.ea_t) -> None:
        """Callee address has been updated by the user."""
        logger.info("callee_addr_changed(ea=%d, callee=%d)", ea, callee)
        ev = callee_addr_changed_event(event_name="callee_addr_changed", ea=ea, callee=callee)
        cb(ev)

    def bookmark_changed(self, index: int, pos: ida_moves.lochist_entry_t, desc: str, operation: int) -> None:
        """Bookmarked position changed.

        If desc==None, then the bookmark was deleted."""
        # TODO: this can fail
        ea = pos.place().toea()
        logger.info(
            "bookmark_changed(index=%d, ea=%d, desc=%s, operation=%d)",
            index,
            ea,
            desc,
            operation,
        )
        ev = bookmark_changed_event(event_name="bookmark_changed", index=index, ea=ea, desc=desc, operation=operation)
        cb(ev)

    # TODO: what is opinfo? type?
    # this has more info than op_type_changed
    def changing_op_type(self, ea: ida_idaapi.ea_t, n: int, opinfo) -> None:
        """An operand type (offset, hex, etc...) is to be changed."""
        logger.info("changing_op_type(ea=%d, n=%d, opinfo=%s)", ea, n, opinfo)
        ev = changing_op_type_event(event_name="changing_op_type", ea=ea, n=n, opinfo=opinfo)
        cb(ev)

    def op_type_changed(self, ea: ida_idaapi.ea_t, n: int) -> None:
        """An operand type (offset, hex, etc...) has been set or deleted.

        Args:
            ea: Address.
            n: Operand number, eventually or'ed with OPND_OUTER or OPND_ALL.
        """
        logger.info("op_type_changed(ea=%d, n=%d)", ea, n)
        ev = op_type_changed_event(event_name="op_type_changed", ea=ea, n=n)
        cb(ev)

    ### dirtree

    # TODO: figure out how to get the dirtree type (bookmarks/functions/etc.)
    def dirtree_mkdir(self, dt: ida_dirtree.dirtree_t, path: str) -> None:
        """Dirtree: a directory has been created."""
        logger.info("dirtree_mkdir(path=%s)", path)
        ev = dirtree_mkdir_event(event_name="dirtree_mkdir", path=path)
        cb(ev)

    def dirtree_rmdir(self, dt: ida_dirtree.dirtree_t, path: str) -> None:
        """Dirtree: a directory has been deleted."""
        logger.info("dirtree_rmdir(path=%s)", path)
        ev = dirtree_rmdir_event(event_name="dirtree_rmdir", path=path)
        cb(ev)

    def dirtree_link(self, dt: ida_dirtree.dirtree_t, path: str, link: bool) -> None:
        """Dirtree: an item has been linked/unlinked."""
        logger.info("dirtree_link(path=%s, link=%s)", path, link)
        ev = dirtree_link_event(event_name="dirtree_link", path=path, link=link)
        cb(ev)

    def dirtree_move(self, dt: ida_dirtree.dirtree_t, _from: str, to: str) -> None:
        """Dirtree: a directory or item has been moved."""
        logger.info("dirtree_move(_from=%s, to=%s)", _from, to)
        ev = dirtree_move_event(event_name="dirtree_move", _from=_from, to=to)
        cb(ev)

    def dirtree_rank(self, dt: ida_dirtree.dirtree_t, path: str, rank: int) -> None:
        """Dirtree: a directory or item rank has been changed."""
        logger.info("dirtree_rank(path=%s, rank=%d)", path, rank)
        ev = dirtree_rank_event(event_name="dirtree_rank", path=path, rank=rank)
        cb(ev)

    def dirtree_rminode(self, dt: ida_dirtree.dirtree_t, inode: int) -> None:
        """Dirtree: an inode became unavailable."""
        logger.info("dirtree_rminode(inode=%d)", inode)
        ev = dirtree_rminode_event(event_name="dirtree_rminode", inode=inode)
        cb(ev)

    def dirtree_segm_moved(self, dt: ida_dirtree.dirtree_t) -> None:
        """Dirtree: inodes were changed due to a segment movement or a program rebasing."""
        logger.info("dirtree_segm_moved()")
        ev = dirtree_segm_moved_event(event_name="dirtree_segm_moved")
        cb(ev)

    ### types

    def changing_ti(
        self,
        ea: ida_idaapi.ea_t,
        new_type,
        new_fnames,
    ) -> None:
        """An item typestring (C/C++ prototype) is to be changed."""
        logger.info("changing_ti(ea=%d, new_type=%s, new_fnames=%s)", ea, new_type, new_fnames)
        ev = changing_ti_event(event_name="changing_ti", ea=ea, new_type=new_type, new_fnames=new_fnames)
        cb(ev)

    def ti_changed(self, ea: ida_idaapi.ea_t, type, fnames) -> None:
        """An item typestring (C/C++ prototype) has been changed."""
        logger.info("ti_changed(ea=%d, type=%s, fnames=%s)", ea, type, fnames)
        ev = ti_changed_event(event_name="ti_changed", ea=ea, type=type, fnames=fnames)
        cb(ev)

    def changing_op_ti(
        self,
        ea: ida_idaapi.ea_t,
        n: int,
        new_type,
        new_fnames,
    ) -> None:
        """An operand typestring (c/c++ prototype) is to be changed."""
        logger.info(
            "changing_op_ti(ea=%d, n=%d, new_type=%s, new_fnames=%s)",
            ea,
            n,
            new_type,
            new_fnames,
        )
        ev = changing_op_ti_event(event_name="changing_op_ti", ea=ea, n=n, new_type=new_type, new_fnames=new_fnames)
        cb(ev)

    def op_ti_changed(
        self,
        ea: ida_idaapi.ea_t,
        n: int,
        type,
        fnames,
    ) -> None:
        """An operand typestring (c/c++ prototype) has been changed."""
        logger.info("op_ti_changed(ea=%d, n=%d, type=%s, fnames=%s)", ea, n, type, fnames)
        ev = op_ti_changed_event(event_name="op_ti_changed", ea=ea, n=n, type=type, fnames=fnames)
        cb(ev)

    ### local types

    def local_types_changed(self, ltc, ordinal: int, name: str) -> None:
        """Local types have been changed.

        Args:
            ltc (local_type_change_t):
            ordinal: 0 means ordinal is unknown
            name: nullptr means name is unknown
        """
        logger.info("local_types_changed(ltc=%s, ordinal=%d, name=%s)", ltc, ordinal, name)
        ev = local_types_changed_event(event_name="local_types_changed", ltc=ltc, ordinal=ordinal, name=name)
        cb(ev)

    def lt_udm_created(self, udtname: str, udm: ida_typeinf.udm_t) -> None:
        """Local type udt member has been added."""
        udm_model = UdmModel.from_udm_t(udm)
        logger.info("lt_udm_created(udtname=%s, udm=%s)", udtname, udm_model.model_dump_json())
        ev = lt_udm_created_event(event_name="lt_udm_created", udtname=udtname, udm=udm_model)
        cb(ev)

    def lt_udm_deleted(self, udtname: str, udm_tid: int, udm: ida_typeinf.udm_t) -> None:
        """Local type udt member has been deleted."""
        udm_model = UdmModel.from_udm_t(udm)
        logger.info("lt_udm_deleted(udtname=%s, udm_tid=%d, udm=%s)", udtname, udm_tid, udm_model.model_dump_json())
        ev = lt_udm_deleted_event(event_name="lt_udm_deleted", udtname=udtname, udm_tid=udm_tid, udm=udm_model)
        cb(ev)

    def lt_udm_renamed(self, udtname: str, udm: ida_typeinf.udm_t, oldname: str) -> None:
        """Local type udt member has been renamed."""
        udm_model = UdmModel.from_udm_t(udm)
        logger.info("lt_udm_renamed(udtname=%s, udm=%s, oldname=%s)", udtname, udm_model.model_dump_json(), oldname)
        ev = lt_udm_renamed_event(event_name="lt_udm_renamed", udtname=udtname, udm=udm_model, oldname=oldname)
        cb(ev)

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
        logger.info(
            "lt_udm_changed(udtname=%s, udm_tid=%d, udmold=%s, udmnew=%s)",
            udtname,
            udm_tid,
            udmold_model.model_dump_json(),
            udmnew_model.model_dump_json(),
        )
        ev = lt_udm_changed_event(
            event_name="lt_udm_changed", udtname=udtname, udm_tid=udm_tid, udmold=udmold_model, udmnew=udmnew_model
        )
        cb(ev)

    def lt_udt_expanded(self, udtname: str, udm_tid: int, delta: int) -> None:
        """A structure type has been expanded/shrank.

        Args:
            udm_tid: The gap was added/removed before this member.
            delta: Number of added/removed bytes.
        """
        logger.info("lt_udt_expanded(udtname=%s, udm_tid=%d, delta=%d)", udtname, udm_tid, delta)
        ev = lt_udt_expanded_event(event_name="lt_udt_expanded", udtname=udtname, udm_tid=udm_tid, delta=delta)
        cb(ev)

    def lt_edm_created(self, enumname: str, edm: ida_typeinf.edm_t) -> None:
        """Local type enum member has been added."""
        edm_model = EdmModel.from_edm_t(edm)
        logger.info("lt_edm_created(enumname=%s, edm=%s)", enumname, edm_model.model_dump_json())
        ev = lt_edm_created_event(event_name="lt_edm_created", enumname=enumname, edm=edm_model)
        cb(ev)

    def lt_edm_deleted(self, enumname: str, edm_tid: int, edm: ida_typeinf.edm_t) -> None:
        """Local type enum member has been deleted."""
        edm_model = EdmModel.from_edm_t(edm)
        logger.info("lt_edm_deleted(enumname=%s, edm_tid=%d, edm=%s)", enumname, edm_tid, edm_model.model_dump_json())
        ev = lt_edm_deleted_event(event_name="lt_edm_deleted", enumname=enumname, edm_tid=edm_tid, edm=edm_model)
        cb(ev)

    def lt_edm_renamed(self, enumname: str, edm: ida_typeinf.edm_t, oldname: str) -> None:
        """Local type enum member has been renamed."""
        edm_model = EdmModel.from_edm_t(edm)
        logger.info("lt_edm_renamed(enumname=%s, edm=%s, oldname=%s)", enumname, edm_model.model_dump_json(), oldname)
        ev = lt_edm_renamed_event(event_name="lt_edm_renamed", enumname=enumname, edm=edm_model, oldname=oldname)
        cb(ev)

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
        logger.info(
            "lt_edm_changed(enumname=%s, edm_tid=%d, edmold=%s, edmnew=%s)",
            enumname,
            edm_tid,
            edmold_model.model_dump_json(),
            edmnew_model.model_dump_json(),
        )
        ev = lt_edm_changed_event(
            event_name="lt_edm_changed", enumname=enumname, edm_tid=edm_tid, edmold=edmold_model, edmnew=edmnew_model
        )
        cb(ev)

    ### frames

    def stkpnts_changed(self, pfn: ida_funcs.func_t) -> None:
        """Stack change points have been modified."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.info("stkpnts_changed(pfn=%s)", pfn_model.model_dump_json())
        ev = stkpnts_changed_event(event_name="stkpnts_changed", pfn=pfn_model)
        cb(ev)

    def frame_created(self, func_ea: ida_idaapi.ea_t) -> None:
        """A function frame has been created.

        See also idb_event::frame_deleted.
        """
        logger.info("frame_created(func_ea=%d)", func_ea)
        ev = frame_created_event(event_name="frame_created", func_ea=func_ea)
        cb(ev)

    def frame_expanded(self, func_ea: ida_idaapi.ea_t, udm_tid: int, delta: int) -> None:
        """A frame type has been expanded/shrank.

        Args:
            udm_tid: The gap was added/removed before this member.
            delta: Number of added/removed bytes.
        """
        logger.info("frame_expanded(func_ea=%d, udm_tid=%d, delta=%d)", func_ea, udm_tid, delta)
        ev = frame_expanded_event(event_name="frame_expanded", func_ea=func_ea, udm_tid=udm_tid, delta=delta)
        cb(ev)

    def frame_deleted(self, pfn: ida_funcs.func_t) -> None:
        """The kernel has deleted a function frame.

        See also idb_event::frame_created.
        """
        pfn_model = FuncModel.from_func_t(pfn)
        logger.info("frame_deleted(pfn=%s)", pfn_model.model_dump_json())
        ev = frame_deleted_event(event_name="frame_deleted", pfn=pfn_model)
        cb(ev)

    def frame_udm_created(self, func_ea: ida_idaapi.ea_t, udm: ida_typeinf.udm_t) -> None:
        """Frame member has been added."""
        udm_model = UdmModel.from_udm_t(udm)
        logger.info("frame_udm_created(func_ea=%d, udm=%s)", func_ea, udm_model.model_dump_json())
        ev = frame_udm_created_event(event_name="frame_udm_created", func_ea=func_ea, udm=udm_model)
        cb(ev)

    def frame_udm_deleted(self, func_ea: ida_idaapi.ea_t, udm_tid: int, udm: ida_typeinf.udm_t) -> None:
        """Frame member has been deleted."""
        udm_model = UdmModel.from_udm_t(udm)
        logger.info("frame_udm_deleted(func_ea=%d, udm_tid=%d, udm=%s)", func_ea, udm_tid, udm_model.model_dump_json())
        ev = frame_udm_deleted_event(event_name="frame_udm_deleted", func_ea=func_ea, udm_tid=udm_tid, udm=udm_model)
        cb(ev)

    def frame_udm_renamed(self, func_ea: ida_idaapi.ea_t, udm: ida_typeinf.udm_t, oldname: str) -> None:
        """Frame member has been renamed."""
        udm_model = UdmModel.from_udm_t(udm)
        logger.info("frame_udm_renamed(func_ea=%d, udm=%s, oldname=%s)", func_ea, udm_model.model_dump_json(), oldname)
        ev = frame_udm_renamed_event(event_name="frame_udm_renamed", func_ea=func_ea, udm=udm_model, oldname=oldname)
        cb(ev)

    def frame_udm_changed(
        self,
        func_ea: ida_idaapi.ea_t,
        udm_tid: int,
        udmold: ida_typeinf.udm_t,
        udmnew: ida_typeinf.udm_t,
    ) -> None:
        """Frame member has been changed."""
        udmold_model = UdmModel.from_udm_t(udmold)
        udmnew_model = UdmModel.from_udm_t(udmnew)
        logger.info(
            "frame_udm_changed(func_ea=%d, udm_tid=%d, udmold=%s, udmnew=%s)",
            func_ea,
            udm_tid,
            udmold_model.model_dump_json(),
            udmnew_model.model_dump_json(),
        )
        ev = frame_udm_changed_event(
            event_name="frame_udm_changed", func_ea=func_ea, udm_tid=udm_tid, udmold=udmold_model, udmnew=udmnew_model
        )
        cb(ev)


# Remaining operation event classes


class determined_main_event(BaseModel):

    event_name: Literal["determined_main"]
    main: int


class extlang_changed_event(BaseModel):

    event_name: Literal["extlang_changed"]
    kind: int
    el: Any
    idx: int


class idasgn_matched_ea_event(BaseModel):

    event_name: Literal["idasgn_matched_ea"]
    ea: int
    name: str
    lib_name: str


class OplogPluginMod(ida_idaapi.plugmod_t):
    def __init__(self):
        self.idb_hooks: IDBChangedHook | None = None

    def run(self, arg):
        self.idb_hooks = IDBChangedHook()

        self.idb_hooks.hook()

    def term(self):
        if self.idb_hooks is not None:
            self.idb_hooks.unhook()


class OplogPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    help = "Log activity in the current IDB"
    comment = ""
    wanted_name = "Operation Log"
    wanted_hotkey = ""

    def init(self):
        return OplogPluginMod()


def PLUGIN_ENTRY():
    return OplogPlugin()
