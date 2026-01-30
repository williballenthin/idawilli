import logging
import threading
from typing import TYPE_CHECKING, Any, Literal
from datetime import datetime

from pydantic import Field, BaseModel, RootModel, field_validator

if TYPE_CHECKING:
    import ida_ua
    import ida_funcs
    import ida_range
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
    def from_func_t(cls, func: "ida_funcs.func_t") -> "FuncModel":
        """Create FuncModel from ida_funcs.func_t instance."""
        import ida_funcs

        name = ida_funcs.get_func_name(func.start_ea)
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
            name=name if name else None,
        )


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
    def from_op_t(cls, op: "ida_ua.op_t") -> "OpModel":
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


class InsnModel(BaseModel):
    """Pydantic model for ida_ua.insn_t structure."""

    cs: int
    ip: int
    ea: int
    itype: int
    size: int
    auxpref: int
    segpref: int
    insnpref: int
    flags: int
    ops: list[OpModel]

    @classmethod
    def from_insn_t(cls, insn: "ida_ua.insn_t") -> "InsnModel":
        """Create InsnModel from ida_ua.insn_t instance."""
        return cls(
            cs=insn.cs,
            ip=insn.ip,
            ea=insn.ea,
            itype=insn.itype,
            size=insn.size,
            auxpref=insn.auxpref,
            segpref=insn.segpref,
            insnpref=insn.insnpref,
            flags=insn.flags,
            ops=[OpModel.from_op_t(insn.ops[i]) for i in range(8)],
        )


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
    def from_segment_t(cls, segment: "ida_segment.segment_t") -> "SegmentModel":
        """Create SegmentModel from ida_segment.segment_t instance."""
        import ida_segment

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


class RangeModel(BaseModel):
    """Pydantic model for ida_range.range_t structure."""

    start_ea: int
    end_ea: int

    @classmethod
    def from_range_t(cls, range_obj: "ida_range.range_t") -> "RangeModel":
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


class CatchModel(BaseModel):
    """Pydantic model for C++ catch block (catch_t structure)."""

    ranges: list[RangeModel]
    disp: int
    fpreg: int
    obj: int
    type_id: int

    @classmethod
    def from_catch_t(cls, catch_obj) -> "CatchModel":
        return cls(
            ranges=[RangeModel(start_ea=r.start_ea, end_ea=r.end_ea) for r in catch_obj],
            disp=catch_obj.disp,
            fpreg=catch_obj.fpreg,
            obj=catch_obj.obj,
            type_id=catch_obj.type_id,
        )


class SehModel(BaseModel):
    """Pydantic model for SEH exception handler (seh_t structure)."""

    ranges: list[RangeModel]
    disp: int
    fpreg: int
    filter_ranges: list[RangeModel]
    seh_code: int

    @classmethod
    def from_seh_t(cls, seh_obj) -> "SehModel":
        return cls(
            ranges=[RangeModel(start_ea=r.start_ea, end_ea=r.end_ea) for r in seh_obj],
            disp=seh_obj.disp,
            fpreg=seh_obj.fpreg,
            filter_ranges=[RangeModel(start_ea=r.start_ea, end_ea=r.end_ea) for r in seh_obj.filter],
            seh_code=seh_obj.seh_code,
        )


class TryblkModel(BaseModel):
    """Pydantic model for try block (tryblk_t structure)."""

    kind: str
    level: int
    ranges: list[RangeModel]
    catches: list[CatchModel] | None = None
    seh: SehModel | None = None

    @classmethod
    def from_tryblk_t(cls, tb) -> "TryblkModel":
        ranges = [RangeModel(start_ea=r.start_ea, end_ea=r.end_ea) for r in tb]

        kind_map = {0: "none", 1: "seh", 2: "cpp"}
        kind = kind_map.get(tb.get_kind(), "unknown")

        catches = None
        seh = None

        if tb.is_cpp():
            catches = [CatchModel.from_catch_t(c) for c in tb.cpp()]
        elif tb.is_seh():
            seh = SehModel.from_seh_t(tb.seh())

        return cls(
            kind=kind,
            level=tb.level,
            ranges=ranges,
            catches=catches,
            seh=seh,
        )


class UdmModel(BaseModel):
    """Pydantic model for ida_typeinf.udm_t structure."""

    offset: int
    size: int
    name: str
    cmt: str
    type_name: str
    repr: str
    effalign: int
    tafld_bits: int
    fda: int

    @classmethod
    def from_udm_t(cls, udm: "ida_typeinf.udm_t") -> "UdmModel":
        return cls(
            offset=udm.offset,
            size=udm.size,
            name=udm.name,
            cmt=udm.cmt,
            type_name=udm.type.get_type_name() or "(unnamed)",
            repr=str(udm.repr),
            effalign=udm.effalign,
            tafld_bits=udm.tafld_bits,
            fda=udm.fda,
        )


class EdmModel(BaseModel):
    """Pydantic model for ida_typeinf.edm_t structure."""

    name: str
    comment: str
    value: int

    @classmethod
    def from_edm_t(cls, edm: "ida_typeinf.edm_t") -> "EdmModel":
        return cls(
            name=edm.name,
            comment=edm.cmt,
            value=edm.value,
        )


class adding_segm_event(BaseModel):
    event_name: Literal["adding_segm"]
    timestamp: datetime
    s: SegmentModel


class segm_added_event(BaseModel):
    event_name: Literal["segm_added"]
    timestamp: datetime
    s: SegmentModel


class deleting_segm_event(BaseModel):
    event_name: Literal["deleting_segm"]
    timestamp: datetime
    start_ea: int


class segm_deleted_event(BaseModel):
    event_name: Literal["segm_deleted"]
    timestamp: datetime
    start_ea: int
    end_ea: int
    flags: int


class changing_segm_start_event(BaseModel):
    event_name: Literal["changing_segm_start"]
    timestamp: datetime
    s: SegmentModel
    new_start: int
    segmod_flags: int


class segm_start_changed_event(BaseModel):
    event_name: Literal["segm_start_changed"]
    timestamp: datetime
    s: SegmentModel
    oldstart: int


class changing_segm_end_event(BaseModel):
    event_name: Literal["changing_segm_end"]
    timestamp: datetime
    s: SegmentModel
    new_end: int
    segmod_flags: int


class segm_end_changed_event(BaseModel):
    event_name: Literal["segm_end_changed"]
    timestamp: datetime
    s: SegmentModel
    oldend: int


class changing_segm_name_event(BaseModel):
    event_name: Literal["changing_segm_name"]
    timestamp: datetime
    s: SegmentModel
    oldname: str


class segm_name_changed_event(BaseModel):
    event_name: Literal["segm_name_changed"]
    timestamp: datetime
    s: SegmentModel
    name: str


class changing_segm_class_event(BaseModel):
    event_name: Literal["changing_segm_class"]
    timestamp: datetime
    s: SegmentModel


class segm_class_changed_event(BaseModel):
    event_name: Literal["segm_class_changed"]
    timestamp: datetime
    s: SegmentModel
    sclass: str


class segm_attrs_updated_event(BaseModel):
    event_name: Literal["segm_attrs_updated"]
    timestamp: datetime
    s: SegmentModel


class segm_moved_event(BaseModel):
    model_config = {"populate_by_name": True}

    event_name: Literal["segm_moved"]
    timestamp: datetime
    from_ea: int = Field(alias="_from")
    to: int
    size: int
    changed_netmap: bool


class SegmMoveInfoModel(BaseModel):
    """Pydantic model for ida_moves.segm_move_info_t structure."""

    from_ea: int
    to_ea: int
    size: int

    @classmethod
    def from_segm_move_info_t(cls, info) -> "SegmMoveInfoModel":
        return cls(
            from_ea=info._from,
            to_ea=info.to,
            size=info.size,
        )


class allsegs_moved_event(BaseModel):
    event_name: Literal["allsegs_moved"]
    timestamp: datetime
    moves: list[SegmMoveInfoModel]


class func_added_event(BaseModel):
    event_name: Literal["func_added"]
    timestamp: datetime
    pfn: FuncModel


class func_updated_event(BaseModel):
    event_name: Literal["func_updated"]
    timestamp: datetime
    pfn: FuncModel


class set_func_start_event(BaseModel):
    event_name: Literal["set_func_start"]
    timestamp: datetime
    pfn: FuncModel
    new_start: int


class set_func_end_event(BaseModel):
    event_name: Literal["set_func_end"]
    timestamp: datetime
    pfn: FuncModel
    new_end: int


class deleting_func_event(BaseModel):
    event_name: Literal["deleting_func"]
    timestamp: datetime
    pfn: FuncModel


class func_deleted_event(BaseModel):
    event_name: Literal["func_deleted"]
    timestamp: datetime
    func_ea: int
    func_name: str | None = None


class thunk_func_created_event(BaseModel):
    event_name: Literal["thunk_func_created"]
    timestamp: datetime
    pfn: FuncModel


class func_tail_appended_event(BaseModel):
    event_name: Literal["func_tail_appended"]
    timestamp: datetime
    pfn: FuncModel
    tail: FuncModel


class deleting_func_tail_event(BaseModel):
    event_name: Literal["deleting_func_tail"]
    timestamp: datetime
    pfn: FuncModel
    tail: RangeModel


class func_tail_deleted_event(BaseModel):
    event_name: Literal["func_tail_deleted"]
    timestamp: datetime
    pfn: FuncModel
    tail_ea: int


class tail_owner_changed_event(BaseModel):
    event_name: Literal["tail_owner_changed"]
    timestamp: datetime
    tail: FuncModel
    owner_func: int
    old_owner: int


class func_noret_changed_event(BaseModel):
    event_name: Literal["func_noret_changed"]
    timestamp: datetime
    pfn: FuncModel


class updating_tryblks_event(BaseModel):
    event_name: Literal["updating_tryblks"]
    timestamp: datetime
    tryblks: list[TryblkModel]


class tryblks_updated_event(BaseModel):
    event_name: Literal["tryblks_updated"]
    timestamp: datetime
    tryblks: list[TryblkModel]


class deleting_tryblks_event(BaseModel):
    event_name: Literal["deleting_tryblks"]
    timestamp: datetime
    range: RangeModel


class changing_cmt_event(BaseModel):
    event_name: Literal["changing_cmt"]
    timestamp: datetime
    ea: int
    repeatable_cmt: bool
    # TODO: add existing comment
    newcmt: str


class cmt_changed_event(BaseModel):
    event_name: Literal["cmt_changed"]
    timestamp: datetime
    ea: int
    # TODO: add the new comment string
    repeatable_cmt: bool


class changing_range_cmt_event(BaseModel):
    event_name: Literal["changing_range_cmt"]
    timestamp: datetime
    kind: Any
    a: RangeModel
    cmt: str
    repeatable: bool


class range_cmt_changed_event(BaseModel):
    event_name: Literal["range_cmt_changed"]
    timestamp: datetime
    kind: Any
    a: RangeModel
    cmt: str
    repeatable: bool


class extra_cmt_changed_event(BaseModel):
    event_name: Literal["extra_cmt_changed"]
    timestamp: datetime
    ea: int
    line_idx: int
    cmt: str


class sgr_changed_event(BaseModel):
    event_name: Literal["sgr_changed"]
    timestamp: datetime
    start_ea: int
    end_ea: int
    regnum: int
    value: Any
    old_value: Any
    tag: int


class sgr_deleted_event(BaseModel):
    event_name: Literal["sgr_deleted"]
    timestamp: datetime
    start_ea: int
    end_ea: int
    regnum: int


class make_code_event(BaseModel):
    event_name: Literal["make_code"]
    timestamp: datetime
    insn: InsnModel


class make_data_event(BaseModel):
    event_name: Literal["make_data"]
    timestamp: datetime
    ea: int
    flags: int
    type_name: str
    len: int


class destroyed_items_event(BaseModel):
    event_name: Literal["destroyed_items"]
    timestamp: datetime
    ea1: int
    ea2: int
    will_disable_range: bool


class renamed_event(BaseModel):
    event_name: Literal["renamed"]
    timestamp: datetime
    ea: int
    new_name: str
    local_name: bool
    old_name: str


class byte_patched_event(BaseModel):
    event_name: Literal["byte_patched"]
    timestamp: datetime
    ea: int
    old_value: int


class item_color_changed_event(BaseModel):
    event_name: Literal["item_color_changed"]
    timestamp: datetime
    ea: int
    color: Any


class callee_addr_changed_event(BaseModel):
    event_name: Literal["callee_addr_changed"]
    timestamp: datetime
    ea: int
    callee: int


class bookmark_changed_event(BaseModel):
    event_name: Literal["bookmark_changed"]
    timestamp: datetime
    index: int
    ea: int
    desc: str
    operation: int


class changing_op_type_event(BaseModel):
    event_name: Literal["changing_op_type"]
    timestamp: datetime
    ea: int
    n: int
    # TODO: this is pretty complex and not directly serializable
    # opinfo: Any


class op_type_changed_event(BaseModel):
    event_name: Literal["op_type_changed"]
    timestamp: datetime
    ea: int
    n: int


class dirtree_mkdir_event(BaseModel):
    event_name: Literal["dirtree_mkdir"]
    timestamp: datetime
    path: str


class dirtree_rmdir_event(BaseModel):
    event_name: Literal["dirtree_rmdir"]
    timestamp: datetime
    path: str


class dirtree_link_event(BaseModel):
    event_name: Literal["dirtree_link"]
    timestamp: datetime
    path: str
    link: bool


class dirtree_move_event(BaseModel):
    model_config = {"populate_by_name": True}

    event_name: Literal["dirtree_move"]
    timestamp: datetime
    from_path: str = Field(alias="_from")
    to: str


class dirtree_rank_event(BaseModel):
    event_name: Literal["dirtree_rank"]
    timestamp: datetime
    path: str
    rank: int


class dirtree_rminode_event(BaseModel):
    event_name: Literal["dirtree_rminode"]
    timestamp: datetime
    inode: int


class dirtree_segm_moved_event(BaseModel):
    event_name: Literal["dirtree_segm_moved"]
    timestamp: datetime


class changing_ti_event(BaseModel):
    event_name: Literal["changing_ti"]
    timestamp: datetime
    ea: int
    new_type: bytes
    new_fnames: bytes
    new_type_str: str | None = None


class ti_changed_event(BaseModel):
    event_name: Literal["ti_changed"]
    timestamp: datetime
    ea: int
    type: bytes
    fnames: bytes
    type_str: str | None = None


class changing_op_ti_event(BaseModel):
    event_name: Literal["changing_op_ti"]
    timestamp: datetime
    ea: int
    n: int
    new_type: bytes
    new_fnames: bytes
    new_type_str: str | None = None


class op_ti_changed_event(BaseModel):
    event_name: Literal["op_ti_changed"]
    timestamp: datetime
    ea: int
    n: int
    type: bytes
    fnames: bytes
    type_str: str | None = None


class local_types_changed_event(BaseModel):
    event_name: Literal["local_types_changed"]
    timestamp: datetime
    ltc: Any
    ordinal: int
    name: str | None


class lt_udm_created_event(BaseModel):
    event_name: Literal["lt_udm_created"]
    timestamp: datetime
    udtname: str
    udm: UdmModel


class lt_udm_deleted_event(BaseModel):
    event_name: Literal["lt_udm_deleted"]
    timestamp: datetime
    udtname: str
    udm: UdmModel


class lt_udm_renamed_event(BaseModel):
    event_name: Literal["lt_udm_renamed"]
    timestamp: datetime
    udtname: str
    udm: UdmModel
    oldname: str


class lt_udm_changed_event(BaseModel):
    event_name: Literal["lt_udm_changed"]
    timestamp: datetime
    udtname: str
    udmold: UdmModel
    udmnew: UdmModel


class lt_udt_expanded_event(BaseModel):
    event_name: Literal["lt_udt_expanded"]
    timestamp: datetime
    udtname: str
    udm_name: str
    delta: int


class lt_edm_created_event(BaseModel):
    event_name: Literal["lt_edm_created"]
    timestamp: datetime
    enumname: str
    edm: EdmModel


class lt_edm_deleted_event(BaseModel):
    event_name: Literal["lt_edm_deleted"]
    timestamp: datetime
    enumname: str
    edm: EdmModel


class lt_edm_renamed_event(BaseModel):
    event_name: Literal["lt_edm_renamed"]
    timestamp: datetime
    enumname: str
    edm: EdmModel
    oldname: str


class lt_edm_changed_event(BaseModel):
    event_name: Literal["lt_edm_changed"]
    timestamp: datetime
    enumname: str
    edmold: EdmModel
    edmnew: EdmModel


class stkpnts_changed_event(BaseModel):
    event_name: Literal["stkpnts_changed"]
    timestamp: datetime
    pfn: FuncModel


class frame_created_event(BaseModel):
    event_name: Literal["frame_created"]
    timestamp: datetime
    func_ea: int
    func_name: str | None = None


class frame_expanded_event(BaseModel):
    event_name: Literal["frame_expanded"]
    timestamp: datetime
    func_ea: int
    func_name: str | None = None
    udm_name: str
    delta: int


class frame_deleted_event(BaseModel):
    event_name: Literal["frame_deleted"]
    timestamp: datetime
    pfn: FuncModel


class frame_udm_created_event(BaseModel):
    event_name: Literal["frame_udm_created"]
    timestamp: datetime
    func_ea: int
    func_name: str | None = None
    udm: UdmModel


class frame_udm_deleted_event(BaseModel):
    event_name: Literal["frame_udm_deleted"]
    timestamp: datetime
    func_ea: int
    func_name: str | None = None
    udm: UdmModel


class frame_udm_renamed_event(BaseModel):
    event_name: Literal["frame_udm_renamed"]
    timestamp: datetime
    func_ea: int
    func_name: str | None = None
    udm: UdmModel
    oldname: str


class frame_udm_changed_event(BaseModel):
    event_name: Literal["frame_udm_changed"]
    timestamp: datetime
    func_ea: int
    func_name: str | None = None
    udmold: UdmModel
    udmnew: UdmModel


class determined_main_event(BaseModel):
    event_name: Literal["determined_main"]
    timestamp: datetime
    main: int


class idasgn_matched_ea_event(BaseModel):
    event_name: Literal["idasgn_matched_ea"]
    timestamp: datetime
    ea: int
    name: str
    lib_name: str


idb_event = (
    renamed_event
    | make_code_event
    | make_data_event
    | func_added_event
    | segm_added_event
    | segm_moved_event
    | ti_changed_event
    | adding_segm_event
    | changing_ti_event
    | cmt_changed_event
    | sgr_changed_event
    | sgr_deleted_event
    | byte_patched_event
    | changing_cmt_event
    | dirtree_link_event
    | dirtree_move_event
    | dirtree_rank_event
    | func_deleted_event
    | func_updated_event
    | segm_deleted_event
    | set_func_end_event
    | allsegs_moved_event
    | deleting_func_event
    | deleting_segm_event
    | dirtree_mkdir_event
    | dirtree_rmdir_event
    | frame_created_event
    | frame_deleted_event
    | op_ti_changed_event
    | changing_op_ti_event
    | frame_expanded_event
    | lt_edm_changed_event
    | lt_edm_created_event
    | lt_edm_deleted_event
    | lt_edm_renamed_event
    | lt_udm_changed_event
    | lt_udm_created_event
    | lt_udm_deleted_event
    | lt_udm_renamed_event
    | set_func_start_event
    | destroyed_items_event
    | determined_main_event
    | dirtree_rminode_event
    | lt_udt_expanded_event
    | op_type_changed_event
    | stkpnts_changed_event
    | tryblks_updated_event
    | bookmark_changed_event
    | changing_op_type_event
    | deleting_tryblks_event
    | segm_end_changed_event
    | updating_tryblks_event
    | changing_segm_end_event
    | extra_cmt_changed_event
    | frame_udm_changed_event
    | frame_udm_created_event
    | frame_udm_deleted_event
    | frame_udm_renamed_event
    | func_tail_deleted_event
    | idasgn_matched_ea_event
    | range_cmt_changed_event
    | segm_name_changed_event
    | changing_range_cmt_event
    | changing_segm_name_event
    | deleting_func_tail_event
    | dirtree_segm_moved_event
    | func_noret_changed_event
    | func_tail_appended_event
    | item_color_changed_event
    | segm_attrs_updated_event
    | segm_class_changed_event
    | segm_start_changed_event
    | tail_owner_changed_event
    | thunk_func_created_event
    | callee_addr_changed_event
    | changing_segm_class_event
    | changing_segm_start_event
    | local_types_changed_event
)


class current_item_changed_event(BaseModel):
    event_name: Literal["current_item_changed"]
    timestamp: datetime
    current_item_ea: int
    current_item_name: str
    prev_item_ea: int
    prev_item_name: str


ui_event = current_item_changed_event


EventList = RootModel[list[idb_event | ui_event]]


class Events:
    def __init__(self, initial_events: list[idb_event | ui_event]):
        self.events: list[idb_event | ui_event] = initial_events
        self.has_new = threading.Event()

    def add_event(self, event: idb_event | ui_event):
        self.events.append(event)
        self.has_new.set()

    def clear(self):
        self.events.clear()
        # re-render since this changed
        self.has_new.set()

    def __iter__(self):
        return iter(self.events)

    def __len__(self):
        return len(self.events)

    def to_json(self):
        return EventList(self.events).model_dump_json()

    @classmethod
    def from_json(cls, json_str: str):
        return cls(EventList.model_validate_json(json_str).root)
