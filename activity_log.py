import logging
from typing import List, Optional

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
    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=True,
        frozen=False,
    )

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
    name: Optional[str] = None
    
    @classmethod
    def from_func_t(cls, func: ida_funcs.func_t) -> 'FuncModel':
        """Create FuncModel from ida_funcs.func_t instance.
        
        Args:
            func: The func_t instance to convert.
            
        Returns:
            FuncModel instance with populated attributes.
        """
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
            name=func.get_name() if hasattr(func, 'get_name') else None,
        )
   


class OpModel(BaseModel):
    """Pydantic model for ida_ua.op_t structure."""

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=True,
        frozen=False,
    )

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
    def from_op_t(cls, op: ida_ua.op_t) -> 'OpModel':
        """Create OpModel from ida_ua.op_t instance.
        
        Args:
            op: The op_t instance to convert.
            
        Returns:
            OpModel instance with populated attributes.
        """
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

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=True,
        frozen=False,
    )

    cs: int
    ip: int
    ea: int
    itype: int
    size: int
    auxpref: int
    auxpref_u16: List[int]
    auxpref_u8: List[int]
    segpref: int
    insnpref: int
    flags: int
    ops: List[OpModel]

    @classmethod
    def from_insn_t(cls, insn: ida_ua.insn_t) -> 'InsnModel':
        """Create InsnModel from ida_ua.insn_t instance.
        
        Args:
            insn: The insn_t instance to convert.
            
        Returns:
            InsnModel instance with populated attributes.
        """
        # Convert auxpref to arrays
        auxpref_u16 = [
            insn.auxpref_u16[0] if hasattr(insn, 'auxpref_u16') and len(insn.auxpref_u16) > 0 else 0,
            insn.auxpref_u16[1] if hasattr(insn, 'auxpref_u16') and len(insn.auxpref_u16) > 1 else 0,
        ]
        
        auxpref_u8 = [
            insn.auxpref_u8[0] if hasattr(insn, 'auxpref_u8') and len(insn.auxpref_u8) > 0 else 0,
            insn.auxpref_u8[1] if hasattr(insn, 'auxpref_u8') and len(insn.auxpref_u8) > 1 else 0,
            insn.auxpref_u8[2] if hasattr(insn, 'auxpref_u8') and len(insn.auxpref_u8) > 2 else 0,
            insn.auxpref_u8[3] if hasattr(insn, 'auxpref_u8') and len(insn.auxpref_u8) > 3 else 0,
        ]
        
        # Convert operands array to OpModel list
        ops = []
        for i in range(8):  # insn_t has 8 operands max
            try:
                op = insn.ops[i] if hasattr(insn, 'ops') and i < len(insn.ops) else insn[i]
                ops.append(OpModel.from_op_t(op))
            except (IndexError, AttributeError):
                # Create a void operand if not available
                ops.append(OpModel(
                    n=i, type=ida_ua.o_void, offb=0, offo=0, flags=0, dtype=0,
                    reg=0, phrase=0, value=0, addr=0, specval=0,
                    specflag1=0, specflag2=0, specflag3=0, specflag4=0
                ))
        
        return cls(
            cs=insn.cs,
            ip=insn.ip,
            ea=insn.ea,
            itype=insn.itype,
            size=insn.size,
            auxpref=insn.auxpref,
            auxpref_u16=auxpref_u16,
            auxpref_u8=auxpref_u8,
            segpref=insn.segpref,
            insnpref=insn.insnpref,
            flags=insn.flags,
            ops=ops,
        )


class SegmentModel(BaseModel):
    """Pydantic model for ida_segment.segment_t structure."""

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=True,
        frozen=False,
    )

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
    defsr: List[int]
    type: int
    color: int
    segment_name: Optional[str] = None
    segment_class: Optional[str] = None
    
    @field_validator('bitness')
    @classmethod
    def validate_bitness(cls, v: int) -> int:
        """Validate bitness is in range 0-2."""
        if v not in (0, 1, 2):
            raise ValueError('bitness must be 0 (16bit), 1 (32bit), or 2 (64bit)')
        return v
    
    @field_validator('defsr')
    @classmethod
    def validate_defsr_length(cls, v: List[int]) -> List[int]:
        """Validate defsr list has exactly 16 elements."""
        if len(v) != 16:
            raise ValueError(f'defsr must have exactly 16 elements, got {len(v)}')
        return v
    
    @field_validator('align')
    @classmethod
    def validate_align(cls, v: int) -> int:
        """Validate align is in range 0-255."""
        if not (0 <= v <= 255):
            raise ValueError(f'align must be in range 0-255, got {v}')
        return v
    
    @field_validator('comb')
    @classmethod
    def validate_comb(cls, v: int) -> int:
        """Validate comb is in range 0-255."""
        if not (0 <= v <= 255):
            raise ValueError(f'comb must be in range 0-255, got {v}')
        return v
    
    @field_validator('perm')
    @classmethod  
    def validate_perm(cls, v: int) -> int:
        """Validate perm is in range 0-255."""
        if not (0 <= v <= 255):
            raise ValueError(f'perm must be in range 0-255, got {v}')
        return v
    
    @field_validator('type')
    @classmethod
    def validate_type(cls, v: int) -> int:
        """Validate type is in range 0-255."""
        if not (0 <= v <= 255):
            raise ValueError(f'type must be in range 0-255, got {v}')
        return v
    
    @field_validator('flags')
    @classmethod
    def validate_flags(cls, v: int) -> int:
        """Validate flags is in range 0-65535."""
        if not (0 <= v <= 65535):
            raise ValueError(f'flags must be in range 0-65535, got {v}')
        return v
    
    @classmethod
    def from_segment_t(cls, segment: ida_segment.segment_t) -> 'SegmentModel':
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


class RangeModel(BaseModel):
    """Pydantic model for ida_range.range_t structure."""

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=True,
        frozen=False,
    )

    start_ea: int
    end_ea: int

    @classmethod
    def from_range_t(cls, range_obj: ida_range.range_t) -> 'RangeModel':
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
    

class FlowChartModel(BaseModel):
    """Pydantic model for ida_gdl.qflow_chart_t structure."""

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=True,
        frozen=False,
    )

    pfn: int
    flags: int
    blocks_count: int
    entry_ea: Optional[int] = None
    function_name: Optional[str] = None

    @classmethod
    def from_qflow_chart_t(cls, fc: ida_gdl.qflow_chart_t) -> 'FlowChartModel':
        """Create FlowChartModel from ida_gdl.qflow_chart_t instance.
        
        Args:
            fc: The qflow_chart_t instance to convert.
            
        Returns:
            FlowChartModel instance with populated attributes.
        """
        # Extract basic information from flow chart
        pfn_addr = fc.pfn.start_ea if hasattr(fc, 'pfn') and fc.pfn else 0
        blocks_count = len(fc) if hasattr(fc, '__len__') else 0
        flags = fc.flags if hasattr(fc, 'flags') else 0
        
        # Try to get entry point
        entry_ea = None
        if hasattr(fc, 'pfn') and fc.pfn:
            entry_ea = fc.pfn.start_ea
        
        # Try to get function name
        function_name = None
        if hasattr(fc, 'pfn') and fc.pfn and hasattr(fc.pfn, 'get_name'):
            function_name = fc.pfn.get_name()
        
        return cls(
            pfn=pfn_addr,
            flags=flags,
            blocks_count=blocks_count,
            entry_ea=entry_ea,
            function_name=function_name,
        )


class LochistEntryModel(BaseModel):
    """Pydantic model for ida_moves.lochist_entry_t structure."""

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=True,
        frozen=False,
    )

    ea: int
    lnnum: int
    x: int
    y: int
    flags: int
    place_type: Optional[str] = None

    @classmethod
    def from_lochist_entry_t(cls, entry: ida_moves.lochist_entry_t) -> 'LochistEntryModel':
        """Create LochistEntryModel from ida_moves.lochist_entry_t instance.
        
        Args:
            entry: The lochist_entry_t instance to convert.
            
        Returns:
            LochistEntryModel instance with populated attributes.
        """
        return cls(
            ea=entry.ea if hasattr(entry, 'ea') else 0,
            lnnum=entry.lnnum if hasattr(entry, 'lnnum') else 0,
            x=entry.x if hasattr(entry, 'x') else 0,
            y=entry.y if hasattr(entry, 'y') else 0,
            flags=entry.flags if hasattr(entry, 'flags') else 0,
            place_type=str(type(entry.place)) if hasattr(entry, 'place') and entry.place else None,
        )
   


class DirtreeModel(BaseModel):
    """Pydantic model for ida_dirtree.dirtree_t structure."""

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=True,
        frozen=False,
    )

    dirtree_id: int
    flags: int
    root_cursor_ea: Optional[int] = None
    title: Optional[str] = None

    @classmethod
    def from_dirtree_t(cls, dt: ida_dirtree.dirtree_t) -> 'DirtreeModel':
        """Create DirtreeModel from ida_dirtree.dirtree_t instance.
        
        Args:
            dt: The dirtree_t instance to convert.
            
        Returns:
            DirtreeModel instance with populated attributes.
        """
        # Extract basic information
        dirtree_id = id(dt)  # Use Python object id as identifier
        flags = dt.flags if hasattr(dt, 'flags') else 0
        
        # Try to get cursor information
        root_cursor_ea = None
        if hasattr(dt, 'get_cursor') and hasattr(dt, 'get_root_cursor'):
            try:
                cursor = dt.get_root_cursor()
                if cursor and hasattr(cursor, 'ea'):
                    root_cursor_ea = cursor.ea
            except:
                pass
        
        # Try to get title
        title = None
        if hasattr(dt, 'get_title'):
            try:
                title = dt.get_title()
            except:
                pass
        
        return cls(
            dirtree_id=dirtree_id,
            flags=flags,
            root_cursor_ea=root_cursor_ea,
            title=title,
        )
   


class UdmModel(BaseModel):
    """Pydantic model for ida_typeinf.udm_t structure."""

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=True,
        frozen=False,
    )

    name: str
    type_str: str
    offset: int
    size: int
    flags: int
    type_id: Optional[int] = None
    comment: Optional[str] = None

    @classmethod
    def from_udm_t(cls, udm: ida_typeinf.udm_t) -> 'UdmModel':
        """Create UdmModel from ida_typeinf.udm_t instance.
        
        Args:
            udm: The udm_t instance to convert.
            
        Returns:
            UdmModel instance with populated attributes.
        """
        # Extract member information
        name = udm.name if hasattr(udm, 'name') else ""
        type_str = str(udm.type) if hasattr(udm, 'type') else ""
        offset = udm.offset if hasattr(udm, 'offset') else 0
        size = udm.size if hasattr(udm, 'size') else 0
        flags = udm.flags if hasattr(udm, 'flags') else 0
        
        # Try to get type ID
        type_id = None
        if hasattr(udm, 'tid'):
            type_id = udm.tid
        elif hasattr(udm, 'type') and hasattr(udm.type, 'get_tid'):
            try:
                type_id = udm.type.get_tid()
            except:
                pass
        
        # Try to get comment
        comment = None
        if hasattr(udm, 'cmt'):
            comment = udm.cmt
        
        return cls(
            name=name,
            type_str=type_str,
            offset=offset,
            size=size,
            flags=flags,
            type_id=type_id,
            comment=comment,
        )


class EdmModel(BaseModel):
    """Pydantic model for ida_typeinf.edm_t structure."""

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=True,
        frozen=False,
    )

    name: str
    value: int
    serial: int
    bmask: int
    comment: Optional[str] = None

    @classmethod
    def from_edm_t(cls, edm: ida_typeinf.edm_t) -> 'EdmModel':
        """Create EdmModel from ida_typeinf.edm_t instance.
        
        Args:
            edm: The edm_t instance to convert.
            
        Returns:
            EdmModel instance with populated attributes.
        """
        # Extract enum member information
        name = edm.name if hasattr(edm, 'name') else ""
        value = edm.value if hasattr(edm, 'value') else 0
        serial = edm.serial if hasattr(edm, 'serial') else 0
        bmask = edm.bmask if hasattr(edm, 'bmask') else 0
        
        # Try to get comment
        comment = None
        if hasattr(edm, 'cmt'):
            comment = edm.cmt
        
        return cls(
            name=name,
            value=value,
            serial=serial,
            bmask=bmask,
            comment=comment,
        )


class IDBChangedHook(ida_idp.IDB_Hooks):
    def closebase(self) -> None:
        """The database will be closed now."""
        logger.info("closebase()")

    def savebase(self) -> None:
        """The database is being saved."""
        logger.info("savebase()")

    def upgraded(self, _from: int) -> None:
        """The database has been upgraded and the receiver can upgrade its info as well.

        Args:
            _from: Version number being upgraded from.
        """
        logger.info("upgraded(_from=%d)", _from)

    def auto_empty(self) -> None:
        """Info: all analysis queues are empty.

        This callback is called once when the initial analysis is finished. If the queue is not empty upon the return from this callback, it will be called later again.
        """
        logger.info("auto_empty()")

    def auto_empty_finally(self) -> None:
        """Info: all analysis queues are empty definitively.

        This callback is called only once.
        """
        logger.info("auto_empty_finally()")

    def determined_main(self, main: ida_idaapi.ea_t) -> None:
        """The main() function has been determined.

        Args:
            main: Address of the main() function.
        """
        logger.info("determined_main(main=%d)", main)

    def extlang_changed(self, kind: int, el, idx: int) -> None:
        """The list of extlangs or the default extlang was changed.

        Args:
            kind: 0: extlang installed, 1: extlang removed, 2: default extlang changed.
            el: Pointer to the extlang affected.
            idx: Extlang index.
        """
        logger.info("extlang_changed(kind=%d, el=%s, idx=%d)", kind, el, idx)

    def idasgn_loaded(self, short_sig_name: str) -> None:
        """FLIRT signature has been loaded for normal processing.

        Not for recognition of startup sequences.

        Args:
            short_sig_name: Short signature name.
        """
        logger.info("idasgn_loaded(short_sig_name=%s)", short_sig_name)

    def kernel_config_loaded(self, pass_number: int) -> None:
        """This event is issued when ida.cfg is parsed.

        Args:
            pass_number: Pass number.
        """
        logger.info("kernel_config_loaded(pass_number=%d)", pass_number)

    def loader_finished(self, li, neflags: int, filetypename: str) -> None:
        """External file loader finished its work.

        Use this event to augment the existing loader functionality.

        Args:
            li: Input file handle.
            neflags: Load file flags.
            filetypename: File type name.
        """
        logger.info(
            "loader_finished(li=%s, neflags=%d, filetypename=%s)",
            li,
            neflags,
            filetypename,
        )

    def flow_chart_created(self, fc: ida_gdl.qflow_chart_t) -> None:
        """Gui has retrieved a function flow chart.

        Plugins may modify the flow chart in this callback.

        Args:
            fc: Flow chart object.
        """
        fc_ = FlowChartModel.from_qflow_chart_t(fc)
        logger.info("flow_chart_created(fc=%s)", fc_.model_dump_json())

    def compiler_changed(self, adjust_inf_fields: bool) -> None:
        """The kernel has changed the compiler information.

        Changes to idainfo::cc structure and get_abi_name.

        Args:
            adjust_inf_fields: May change inf fields?
        """
        logger.info("compiler_changed(adjust_inf_fields=%s)", adjust_inf_fields)

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
        logger.info("changing_ti(ea=%d, new_type=%s, new_fnames=%s)", ea, new_type, new_fnames)

    def ti_changed(self, ea: ida_idaapi.ea_t, type, fnames) -> None:
        """An item typestring (c/c++ prototype) has been changed.

        Args:
            ea: Address.
            type: Type information.
            fnames: Field names.
        """
        logger.info("ti_changed(ea=%d, type=%s, fnames=%s)", ea, type, fnames)

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
        logger.info(
            "changing_op_ti(ea=%d, n=%d, new_type=%s, new_fnames=%s)",
            ea,
            n,
            new_type,
            new_fnames,
        )

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
        logger.info("op_ti_changed(ea=%d, n=%d, type=%s, fnames=%s)", ea, n, type, fnames)

    def changing_op_type(self, ea: ida_idaapi.ea_t, n: int, opinfo) -> None:
        """An operand type (offset, hex, etc...) is to be changed.

        Args:
            ea: Address.
            n: Operand number, eventually or'ed with OPND_OUTER or OPND_ALL.
            opinfo: Additional operand info.
        """
        logger.info("changing_op_type(ea=%d, n=%d, opinfo=%s)", ea, n, opinfo)

    def op_type_changed(self, ea: ida_idaapi.ea_t, n: int) -> None:
        """An operand type (offset, hex, etc...) has been set or deleted.

        Args:
            ea: Address.
            n: Operand number, eventually or'ed with OPND_OUTER or OPND_ALL.
        """
        logger.info("op_type_changed(ea=%d, n=%d)", ea, n)

    def segm_added(self, s: ida_segment.segment_t) -> None:
        """A new segment has been created.

        See also adding_segm.

        Args:
            s: Segment object.
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.info("segm_added(s=%s)", s_model.model_dump_json())

    def deleting_segm(self, start_ea: ida_idaapi.ea_t) -> None:
        """A segment is to be deleted.

        Args:
            start_ea: Start address of segment.
        """
        logger.info("deleting_segm(start_ea=%d)", start_ea)

    def segm_deleted(self, start_ea: ida_idaapi.ea_t, end_ea: ida_idaapi.ea_t, flags: int) -> None:
        """A segment has been deleted.

        Args:
            start_ea: Start address of segment.
            end_ea: End address of segment.
            flags: Deletion flags.
        """
        logger.info("segm_deleted(start_ea=%d, end_ea=%d, flags=%d)", start_ea, end_ea, flags)

    def changing_segm_start(self, s: ida_segment.segment_t, new_start: ida_idaapi.ea_t, segmod_flags: int) -> None:
        """Segment start address is to be changed.

        Args:
            s: Segment object.
            new_start: New start address.
            segmod_flags: Segment modification flags.
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.info(
            "changing_segm_start(s=%s, new_start=%d, segmod_flags=%d)",
            s_model.model_dump_json(),
            new_start,
            segmod_flags,
        )

    def segm_start_changed(self, s: ida_segment.segment_t, oldstart: ida_idaapi.ea_t) -> None:
        """Segment start address has been changed.

        Args:
            s: Segment object.
            oldstart: Old start address.
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.info("segm_start_changed(s=%s, oldstart=%d)", s_model.model_dump_json(), oldstart)

    def changing_segm_end(self, s: ida_segment.segment_t, new_end: ida_idaapi.ea_t, segmod_flags: int) -> None:
        """Segment end address is to be changed.

        Args:
            s: Segment object.
            new_end: New end address.
            segmod_flags: Segment modification flags.
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.info(
            "changing_segm_end(s=%s, new_end=%d, segmod_flags=%d)",
            s_model.model_dump_json(),
            new_end,
            segmod_flags,
        )

    def segm_end_changed(self, s: ida_segment.segment_t, oldend: ida_idaapi.ea_t) -> None:
        """Segment end address has been changed.

        Args:
            s: Segment object.
            oldend: Old end address.
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.info("segm_end_changed(s=%s, oldend=%d)", s_model.model_dump_json(), oldend)

    def changing_segm_name(self, s: ida_segment.segment_t, oldname: str) -> None:
        """Segment name is being changed.

        Args:
            s: Segment object.
            oldname: Old segment name.
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.info("changing_segm_name(s=%s, oldname=%s)", s_model.model_dump_json(), oldname)

    def segm_name_changed(self, s: ida_segment.segment_t, name: str) -> None:
        """Segment name has been changed.

        Args:
            s: Segment object.
            name: New segment name.
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.info("segm_name_changed(s=%s, name=%s)", s_model.model_dump_json(), name)

    def changing_segm_class(self, s: ida_segment.segment_t) -> None:
        """Segment class is being changed.

        Args:
            s: Segment object.
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.info("changing_segm_class(s=%s)", s_model.model_dump_json())

    def segm_class_changed(self, s: ida_segment.segment_t, sclass: str) -> None:
        """Segment class has been changed.

        Args:
            s: Segment object.
            sclass: New segment class.
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.info("segm_class_changed(s=%s, sclass=%s)", s_model.model_dump_json(), sclass)

    def segm_attrs_updated(self, s: ida_segment.segment_t) -> None:
        """Segment attributes has been changed.

        This event is generated for secondary segment attributes (examples: color, permissions, etc).

        Args:
            s: Segment object.
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.info("segm_attrs_updated(s=%s)", s_model.model_dump_json())

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
        logger.info(
            "segm_moved(_from=%d, to=%d, size=%d, changed_netmap=%s)",
            _from,
            to,
            size,
            changed_netmap,
        )

    def allsegs_moved(self, info) -> None:
        """Program rebasing is complete.

        This event is generated after series of segm_moved events.

        Args:
            info: Segment move information.
        """
        logger.info("allsegs_moved(info=%s)", info)

    def func_added(self, pfn: ida_funcs.func_t) -> None:
        """The kernel has added a function.

        Args:
            pfn: Function object.
        """
        pfn_model = FuncModel.from_func_t(pfn)
        logger.info("func_added(pfn=%s)", pfn_model.model_dump_json())

    def func_updated(self, pfn: ida_funcs.func_t) -> None:
        """The kernel has updated a function.

        Args:
            pfn: Function object.
        """
        pfn_model = FuncModel.from_func_t(pfn)
        logger.info("func_updated(pfn=%s)", pfn_model.model_dump_json())

    def set_func_start(self, pfn: ida_funcs.func_t, new_start: ida_idaapi.ea_t) -> None:
        """Function chunk start address will be changed.

        Args:
            pfn: Function object.
            new_start: New start address.
        """
        pfn_model = FuncModel.from_func_t(pfn)
        logger.info("set_func_start(pfn=%s, new_start=%d)", pfn_model.model_dump_json(), new_start)

    def set_func_end(self, pfn: ida_funcs.func_t, new_end: ida_idaapi.ea_t) -> None:
        """Function chunk end address will be changed.

        Args:
            pfn: Function object.
            new_end: New end address.
        """
        pfn_model = FuncModel.from_func_t(pfn)
        logger.info("set_func_end(pfn=%s, new_end=%d)", pfn_model.model_dump_json(), new_end)

    def deleting_func(self, pfn: ida_funcs.func_t) -> None:
        """The kernel is about to delete a function.

        Args:
            pfn: Function object.
        """
        pfn_model = FuncModel.from_func_t(pfn)
        logger.info("deleting_func(pfn=%s)", pfn_model.model_dump_json())

    def frame_deleted(self, pfn: ida_funcs.func_t) -> None:
        """The kernel has deleted a function frame.

        See also idb_event::frame_created.

        Args:
            pfn: Function object.
        """
        pfn_model = FuncModel.from_func_t(pfn)
        logger.info("frame_deleted(pfn=%s)", pfn_model.model_dump_json())

    def thunk_func_created(self, pfn: ida_funcs.func_t) -> None:
        """A thunk bit has been set for a function.

        Args:
            pfn: Function object.
        """
        pfn_model = FuncModel.from_func_t(pfn)
        logger.info("thunk_func_created(pfn=%s)", pfn_model.model_dump_json())

    def func_tail_appended(self, pfn: ida_funcs.func_t, tail: ida_funcs.func_t) -> None:
        """A function tail chunk has been appended.

        Args:
            pfn: Function object.
            tail: Tail function object.
        """
        pfn_model = FuncModel.from_func_t(pfn)
        tail_model = FuncModel.from_func_t(tail)
        logger.info("func_tail_appended(pfn=%s, tail=%s)", pfn_model.model_dump_json(), tail_model.model_dump_json())

    def deleting_func_tail(self, pfn: ida_funcs.func_t, tail: ida_range.range_t) -> None:
        """A function tail chunk is to be removed.

        Args:
            pfn: Function object.
            tail: Range of tail to be removed.
        """
        pfn_model = FuncModel.from_func_t(pfn)
        tail_model = RangeModel.from_range_t(tail)
        logger.info("deleting_func_tail(pfn=%s, tail=%s)", pfn_model.model_dump_json(), tail_model.model_dump_json())

    def func_tail_deleted(self, pfn: ida_funcs.func_t, tail_ea: ida_idaapi.ea_t) -> None:
        """A function tail chunk has been removed.

        Args:
            pfn: Function object.
            tail_ea: Address of removed tail.
        """
        pfn_model = FuncModel.from_func_t(pfn)
        logger.info("func_tail_deleted(pfn=%s, tail_ea=%d)", pfn_model.model_dump_json(), tail_ea)

    def tail_owner_changed(
        self,
        tail: ida_funcs.func_t,
        owner_func: ida_idaapi.ea_t,
        old_owner: ida_idaapi.ea_t,
    ) -> None:
        """A tail chunk owner has been changed.

        Args:
            tail: Tail function object.
            owner_func: New owner function address.
            old_owner: Old owner function address.
        """
        tail_model = FuncModel.from_func_t(tail)
        logger.info(
            "tail_owner_changed(tail=%s, owner_func=%d, old_owner=%d)",
            tail_model.model_dump_json(),
            owner_func,
            old_owner,
        )

    def func_noret_changed(self, pfn: ida_funcs.func_t) -> None:
        """FUNC_NORET bit has been changed.

        Args:
            pfn: Function object.
        """
        pfn_model = FuncModel.from_func_t(pfn)
        logger.info("func_noret_changed(pfn=%s)", pfn_model.model_dump_json())

    def stkpnts_changed(self, pfn: ida_funcs.func_t) -> None:
        """Stack change points have been modified.

        Args:
            pfn: Function object.
        """
        pfn_model = FuncModel.from_func_t(pfn)
        logger.info("stkpnts_changed(pfn=%s)", pfn_model.model_dump_json())

    def updating_tryblks(self, tbv) -> None:
        """About to update tryblk information.

        Args:
            tbv: Try blocks information.
        """
        logger.info("updating_tryblks(tbv=%s)", tbv)

    def tryblks_updated(self, tbv) -> None:
        """Updated tryblk information.

        Args:
            tbv: Try blocks information.
        """
        logger.info("tryblks_updated(tbv=%s)", tbv)

    def deleting_tryblks(self, range: ida_range.range_t) -> None:
        """About to delete tryblk information in given range.

        Args:
            range: Range to delete tryblks from.
        """
        range_model = RangeModel.from_range_t(range)
        logger.info("deleting_tryblks(range=%s)", range_model.model_dump_json())

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
        logger.info(
            "sgr_changed(start_ea=%d, end_ea=%d, regnum=%d, value=%s, old_value=%s, tag=%d)",
            start_ea,
            end_ea,
            regnum,
            value,
            old_value,
            tag,
        )

    def make_code(self, insn: ida_ua.insn_t) -> None:
        """An instruction is being created.

        Args:
            insn: Instruction object.
        """
        insn_model = InsnModel.from_insn_t(insn)
        logger.info("make_code(insn=%s)", insn_model.model_dump_json())

    def make_data(self, ea: ida_idaapi.ea_t, flags: int, tid: int, len: int) -> None:
        """A data item is being created.

        Args:
            ea: Address.
            flags: Data flags.
            tid: Type ID.
            len: Length of data item.
        """
        logger.info("make_data(ea=%d, flags=%d, tid=%d, len=%d)", ea, flags, tid, len)

    def destroyed_items(self, ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t, will_disable_range: bool) -> None:
        """Instructions/data have been destroyed in [ea1,ea2).

        Args:
            ea1: Start address.
            ea2: End address.
            will_disable_range: Whether range will be disabled.
        """
        logger.info(
            "destroyed_items(ea1=%d, ea2=%d, will_disable_range=%s)",
            ea1,
            ea2,
            will_disable_range,
        )

    def renamed(self, ea: ida_idaapi.ea_t, new_name: str, local_name: bool, old_name: str) -> None:
        """The kernel has renamed a byte.

        See also the rename event.

        Args:
            ea: Address.
            new_name: New name (can be None).
            local_name: Whether it's a local name.
            old_name: Old name (can be None).
        """
        logger.info(
            "renamed(ea=%d, new_name=%s, local_name=%s, old_name=%s)",
            ea,
            new_name,
            local_name,
            old_name,
        )

    def byte_patched(self, ea: ida_idaapi.ea_t, old_value: int) -> None:
        """A byte has been patched.

        Args:
            ea: Address.
            old_value: Old byte value.
        """
        logger.info("byte_patched(ea=%d, old_value=%d)", ea, old_value)

    def changing_cmt(self, ea: ida_idaapi.ea_t, repeatable_cmt: bool, newcmt: str) -> None:
        """An item comment is to be changed.

        Args:
            ea: Address.
            repeatable_cmt: Whether it's a repeatable comment.
            newcmt: New comment text.
        """
        logger.info(
            "changing_cmt(ea=%d, repeatable_cmt=%s, newcmt=%s)",
            ea,
            repeatable_cmt,
            newcmt,
        )

    def cmt_changed(self, ea: ida_idaapi.ea_t, repeatable_cmt: bool) -> None:
        """An item comment has been changed.

        Args:
            ea: Address.
            repeatable_cmt: Whether it's a repeatable comment.
        """
        logger.info("cmt_changed(ea=%d, repeatable_cmt=%s)", ea, repeatable_cmt)

    def changing_range_cmt(self, kind, a: ida_range.range_t, cmt: str, repeatable: bool) -> None:
        """Range comment is to be changed.

        Args:
            kind: Range kind.
            a: Range object.
            cmt: Comment text.
            repeatable: Whether it's repeatable.
        """
        a_model = RangeModel.from_range_t(a)
        logger.info(
            "changing_range_cmt(kind=%s, a=%s, cmt=%s, repeatable=%s)",
            kind,
            a_model.model_dump_json(),
            cmt,
            repeatable,
        )

    def range_cmt_changed(self, kind, a: ida_range.range_t, cmt: str, repeatable: bool) -> None:
        """Range comment has been changed.

        Args:
            kind: Range kind.
            a: Range object.
            cmt: Comment text.
            repeatable: Whether it's repeatable.
        """
        a_model = RangeModel.from_range_t(a)
        logger.info(
            "range_cmt_changed(kind=%s, a=%s, cmt=%s, repeatable=%s)",
            kind,
            a_model.model_dump_json(),
            cmt,
            repeatable,
        )

    def extra_cmt_changed(self, ea: ida_idaapi.ea_t, line_idx: int, cmt: str) -> None:
        """An extra comment has been changed.

        Args:
            ea: Address.
            line_idx: Line index.
            cmt: Comment text.
        """
        logger.info("extra_cmt_changed(ea=%d, line_idx=%d, cmt=%s)", ea, line_idx, cmt)

    def item_color_changed(self, ea: ida_idaapi.ea_t, color) -> None:
        """An item color has been changed.

        If color==DEFCOLOR, then the color is deleted.

        Args:
            ea: Address.
            color: Background color.
        """
        logger.info("item_color_changed(ea=%d, color=%s)", ea, color)

    def callee_addr_changed(self, ea: ida_idaapi.ea_t, callee: ida_idaapi.ea_t) -> None:
        """Callee address has been updated by the user.

        Args:
            ea: Address.
            callee: Callee address.
        """
        logger.info("callee_addr_changed(ea=%d, callee=%d)", ea, callee)

    def bookmark_changed(self, index: int, pos: ida_moves.lochist_entry_t, desc: str, operation: int) -> None:
        """Bookmarked position changed.

        If desc==None, then the bookmark was deleted.

        Args:
            index: Bookmark index.
            pos: Location history entry.
            desc: Bookmark description.
            operation: 0-added, 1-updated, 2-deleted.
        """
        pos_model = LochistEntryModel.from_lochist_entry_t(pos)
        logger.info(
            "bookmark_changed(index=%d, pos=%s, desc=%s, operation=%d)",
            index,
            pos_model.model_dump_json(),
            desc,
            operation,
        )

    def sgr_deleted(self, start_ea: ida_idaapi.ea_t, end_ea: ida_idaapi.ea_t, regnum: int) -> None:
        """The kernel has deleted a segment register value.

        Args:
            start_ea: Start address.
            end_ea: End address.
            regnum: Register number.
        """
        logger.info("sgr_deleted(start_ea=%d, end_ea=%d, regnum=%d)", start_ea, end_ea, regnum)

    def adding_segm(self, s: ida_segment.segment_t) -> None:
        """A segment is being created.

        Args:
            s: Segment object.
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.info("adding_segm(s=%s)", s_model.model_dump_json())

    def func_deleted(self, func_ea: ida_idaapi.ea_t) -> None:
        """A function has been deleted.

        Args:
            func_ea: Function address.
        """
        logger.info("func_deleted(func_ea=%d)", func_ea)

    def dirtree_mkdir(self, dt: ida_dirtree.dirtree_t, path: str) -> None:
        """Dirtree: a directory has been created.

        Args:
            dt: Directory tree object.
            path: Directory path.
        """
        dt_model = DirtreeModel.from_dirtree_t(dt)
        logger.info("dirtree_mkdir(dt=%s, path=%s)", dt_model.model_dump_json(), path)

    def dirtree_rmdir(self, dt: ida_dirtree.dirtree_t, path: str) -> None:
        """Dirtree: a directory has been deleted.

        Args:
            dt: Directory tree object.
            path: Directory path.
        """
        dt_model = DirtreeModel.from_dirtree_t(dt)
        logger.info("dirtree_rmdir(dt=%s, path=%s)", dt_model.model_dump_json(), path)

    def dirtree_link(self, dt: ida_dirtree.dirtree_t, path: str, link: bool) -> None:
        """Dirtree: an item has been linked/unlinked.

        Args:
            dt: Directory tree object.
            path: Item path.
            link: Whether item is being linked.
        """
        dt_model = DirtreeModel.from_dirtree_t(dt)
        logger.info("dirtree_link(dt=%s, path=%s, link=%s)", dt_model.model_dump_json(), path, link)

    def dirtree_move(self, dt: ida_dirtree.dirtree_t, _from: str, to: str) -> None:
        """Dirtree: a directory or item has been moved.

        Args:
            dt: Directory tree object.
            _from: Source path.
            to: Destination path.
        """
        dt_model = DirtreeModel.from_dirtree_t(dt)
        logger.info("dirtree_move(dt=%s, _from=%s, to=%s)", dt_model.model_dump_json(), _from, to)

    def dirtree_rank(self, dt: ida_dirtree.dirtree_t, path: str, rank: int) -> None:
        """Dirtree: a directory or item rank has been changed.

        Args:
            dt: Directory tree object.
            path: Item path.
            rank: New rank.
        """
        dt_model = DirtreeModel.from_dirtree_t(dt)
        logger.info("dirtree_rank(dt=%s, path=%s, rank=%d)", dt_model.model_dump_json(), path, rank)

    def dirtree_rminode(self, dt: ida_dirtree.dirtree_t, inode: int) -> None:
        """Dirtree: an inode became unavailable.

        Args:
            dt: Directory tree object.
            inode: Inode number.
        """
        dt_model = DirtreeModel.from_dirtree_t(dt)
        logger.info("dirtree_rminode(dt=%s, inode=%d)", dt_model.model_dump_json(), inode)

    def dirtree_segm_moved(self, dt: ida_dirtree.dirtree_t) -> None:
        """Dirtree: inodes were changed due to a segment movement or a program rebasing.

        Args:
            dt: Directory tree object.
        """
        dt_model = DirtreeModel.from_dirtree_t(dt)
        logger.info("dirtree_segm_moved(dt=%s)", dt_model.model_dump_json())

    def local_types_changed(self, ltc, ordinal: int, name: str) -> None:
        """Local types have been changed.

        Args:
            ltc: Local type change information.
            ordinal: Ordinal (0 means ordinal is unknown).
            name: Type name (None means name is unknown).
        """
        logger.info("local_types_changed(ltc=%s, ordinal=%d, name=%s)", ltc, ordinal, name)

    def lt_udm_created(self, udtname: str, udm: ida_typeinf.udm_t) -> None:
        """Local type udt member has been added.

        Args:
            udtname: UDT name.
            udm: UDT member object.
        """
        udm_model = UdmModel.from_udm_t(udm)
        logger.info("lt_udm_created(udtname=%s, udm=%s)", udtname, udm_model.model_dump_json())

    def lt_udm_deleted(self, udtname: str, udm_tid: int, udm: ida_typeinf.udm_t) -> None:
        """Local type udt member has been deleted.

        Args:
            udtname: UDT name.
            udm_tid: UDT member type ID.
            udm: UDT member object.
        """
        udm_model = UdmModel.from_udm_t(udm)
        logger.info("lt_udm_deleted(udtname=%s, udm_tid=%d, udm=%s)", udtname, udm_tid, udm_model.model_dump_json())

    def lt_udm_renamed(self, udtname: str, udm: ida_typeinf.udm_t, oldname: str) -> None:
        """Local type udt member has been renamed.

        Args:
            udtname: UDT name.
            udm: UDT member object.
            oldname: Old member name.
        """
        udm_model = UdmModel.from_udm_t(udm)
        logger.info("lt_udm_renamed(udtname=%s, udm=%s, oldname=%s)", udtname, udm_model.model_dump_json(), oldname)

    def lt_udm_changed(
        self,
        udtname: str,
        udm_tid: int,
        udmold: ida_typeinf.udm_t,
        udmnew: ida_typeinf.udm_t,
    ) -> None:
        """Local type udt member has been changed.

        Args:
            udtname: UDT name.
            udm_tid: UDT member type ID.
            udmold: Old UDT member object.
            udmnew: New UDT member object.
        """
        udmold_model = UdmModel.from_udm_t(udmold)
        udmnew_model = UdmModel.from_udm_t(udmnew)
        logger.info(
            "lt_udm_changed(udtname=%s, udm_tid=%d, udmold=%s, udmnew=%s)",
            udtname,
            udm_tid,
            udmold_model.model_dump_json(),
            udmnew_model.model_dump_json(),
        )

    def lt_udt_expanded(self, udtname: str, udm_tid: int, delta: int) -> None:
        """A structure type has been expanded/shrank.

        Args:
            udtname: UDT name.
            udm_tid: The gap was added/removed before this member.
            delta: Number of added/removed bytes.
        """
        logger.info("lt_udt_expanded(udtname=%s, udm_tid=%d, delta=%d)", udtname, udm_tid, delta)

    def frame_created(self, func_ea: ida_idaapi.ea_t) -> None:
        """A function frame has been created.

        See also idb_event::frame_deleted.

        Args:
            func_ea: Function address.
        """
        logger.info("frame_created(func_ea=%d)", func_ea)

    def frame_udm_created(self, func_ea: ida_idaapi.ea_t, udm: ida_typeinf.udm_t) -> None:
        """Frame member has been added.

        Args:
            func_ea: Function address.
            udm: UDT member object.
        """
        udm_model = UdmModel.from_udm_t(udm)
        logger.info("frame_udm_created(func_ea=%d, udm=%s)", func_ea, udm_model.model_dump_json())

    def frame_udm_deleted(self, func_ea: ida_idaapi.ea_t, udm_tid: int, udm: ida_typeinf.udm_t) -> None:
        """Frame member has been deleted.

        Args:
            func_ea: Function address.
            udm_tid: UDT member type ID.
            udm: UDT member object.
        """
        udm_model = UdmModel.from_udm_t(udm)
        logger.info("frame_udm_deleted(func_ea=%d, udm_tid=%d, udm=%s)", func_ea, udm_tid, udm_model.model_dump_json())

    def frame_udm_renamed(self, func_ea: ida_idaapi.ea_t, udm: ida_typeinf.udm_t, oldname: str) -> None:
        """Frame member has been renamed.

        Args:
            func_ea: Function address.
            udm: UDT member object.
            oldname: Old member name.
        """
        udm_model = UdmModel.from_udm_t(udm)
        logger.info("frame_udm_renamed(func_ea=%d, udm=%s, oldname=%s)", func_ea, udm_model.model_dump_json(), oldname)

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
        udmold_model = UdmModel.from_udm_t(udmold)
        udmnew_model = UdmModel.from_udm_t(udmnew)
        logger.info(
            "frame_udm_changed(func_ea=%d, udm_tid=%d, udmold=%s, udmnew=%s)",
            func_ea,
            udm_tid,
            udmold_model.model_dump_json(),
            udmnew_model.model_dump_json(),
        )

    def frame_expanded(self, func_ea: ida_idaapi.ea_t, udm_tid: int, delta: int) -> None:
        """A frame type has been expanded/shrank.

        Args:
            func_ea: Function address.
            udm_tid: The gap was added/removed before this member.
            delta: Number of added/removed bytes.
        """
        logger.info("frame_expanded(func_ea=%d, udm_tid=%d, delta=%d)", func_ea, udm_tid, delta)

    def idasgn_matched_ea(self, ea: ida_idaapi.ea_t, name: str, lib_name: str) -> None:
        """A FLIRT match has been found.

        Args:
            ea: The matching address.
            name: The matched name.
            lib_name: Library name extracted from signature file.
        """
        logger.info("idasgn_matched_ea(ea=%d, name=%s, lib_name=%s)", ea, name, lib_name)

    def lt_edm_created(self, enumname: str, edm: ida_typeinf.edm_t) -> None:
        """Local type enum member has been added.

        Args:
            enumname: Enum name.
            edm: Enum member object.
        """
        edm_model = EdmModel.from_edm_t(edm)
        logger.info("lt_edm_created(enumname=%s, edm=%s)", enumname, edm_model.model_dump_json())

    def lt_edm_deleted(self, enumname: str, edm_tid: int, edm: ida_typeinf.edm_t) -> None:
        """Local type enum member has been deleted.

        Args:
            enumname: Enum name.
            edm_tid: Enum member type ID.
            edm: Enum member object.
        """
        edm_model = EdmModel.from_edm_t(edm)
        logger.info("lt_edm_deleted(enumname=%s, edm_tid=%d, edm=%s)", enumname, edm_tid, edm_model.model_dump_json())

    def lt_edm_renamed(self, enumname: str, edm: ida_typeinf.edm_t, oldname: str) -> None:
        """Local type enum member has been renamed.

        Args:
            enumname: Enum name.
            edm: Enum member object.
            oldname: Old member name.
        """
        edm_model = EdmModel.from_edm_t(edm)
        logger.info("lt_edm_renamed(enumname=%s, edm=%s, oldname=%s)", enumname, edm_model.model_dump_json(), oldname)

    def lt_edm_changed(
        self,
        enumname: str,
        edm_tid: int,
        edmold: ida_typeinf.edm_t,
        edmnew: ida_typeinf.edm_t,
    ) -> None:
        """Local type enum member has been changed.

        Args:
            enumname: Enum name.
            edm_tid: Enum member type ID.
            edmold: Old enum member object.
            edmnew: New enum member object.
        """
        edmold_model = EdmModel.from_edm_t(edmold)
        edmnew_model = EdmModel.from_edm_t(edmnew)
        logger.info(
            "lt_edm_changed(enumname=%s, edm_tid=%d, edmold=%s, edmnew=%s)",
            enumname,
            edm_tid,
            edmold_model.model_dump_json(),
            edmnew_model.model_dump_json(),
        )


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
