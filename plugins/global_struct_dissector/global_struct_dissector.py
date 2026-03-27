import logging
import struct
from dataclasses import dataclass
from typing import Iterator

import ida_auto
import ida_bytes
import ida_idaapi
import ida_lines
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import ida_ua
import idaapi

logger = logging.getLogger(__name__)

INDENT_SIZE = 2


@dataclass
class FieldInfo:
    """Represents a single field in a structure."""

    name: str
    offset: int
    size: int
    type_name: str
    tinfo: ida_typeinf.tinfo_t

    is_bitfield: bool = False
    bit_offset: int = 0
    bit_size: int = 0

    is_array: bool = False
    array_size: int = 0
    elem_tinfo: ida_typeinf.tinfo_t | None = None


@dataclass
class FormattedLine:
    """A single line of formatted output with color codes."""

    text: str
    indent: int = 0

    def render(self) -> str:
        """Render with indentation."""
        prefix = " " * (self.indent * INDENT_SIZE)
        return prefix + self.text


@dataclass
class UnwrappedType:
    """Result of unwrapping a type to its base struct/union."""

    tinfo: ida_typeinf.tinfo_t
    is_array: bool = False
    array_count: int = 1


def unwrap_type(tif: ida_typeinf.tinfo_t) -> UnwrappedType | None:
    """
    Unwrap typedefs and arrays to find underlying struct/union.

    Returns None if the underlying type is not a struct/union.
    """
    result = UnwrappedType(tinfo=ida_typeinf.tinfo_t(tif))

    if result.tinfo.is_array():
        result.is_array = True
        result.array_count = result.tinfo.get_array_nelems()
        elem_tif = result.tinfo.get_array_element()
        if elem_tif:
            result.tinfo = elem_tif
        else:
            logger.debug("unwrap_type: array type '%s' has no element type", tif.dstr())

    if not result.tinfo.is_struct() and not result.tinfo.is_union():
        logger.debug("unwrap_type: '%s' is not struct/union", result.tinfo.dstr())
        return None

    return result


def is_global_data_segment(ea: int) -> bool:
    """Check if address is in a global data segment (not stack/code)."""
    seg = ida_segment.getseg(ea)
    if seg is None:
        logger.debug("0x%X: no segment found", ea)
        return False

    seg_type = ida_segment.segtype(ea)
    if seg_type not in (ida_segment.SEG_DATA, ida_segment.SEG_BSS):
        logger.debug(
            "0x%X: segment type %d not DATA/BSS (seg: %s)",
            ea, seg_type, ida_segment.get_segm_name(seg),
        )
        return False
    return True


MAX_FIELDS = 10000


def get_struct_fields(tif: ida_typeinf.tinfo_t) -> list[FieldInfo]:
    """Extract all fields from a structure type."""
    fields = []

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        logger.debug("get_struct_fields: failed to get UDT details for '%s'", tif.dstr())
        return fields

    field_count = udt.size()
    if field_count > MAX_FIELDS:
        logger.warning("Structure has %d fields, truncating to %d", field_count, MAX_FIELDS)
        field_count = MAX_FIELDS

    for i in range(field_count):
        member = udt[i]

        name = member.name if member.name else f"__field_{i:02d}"
        byte_offset = member.offset // 8
        byte_size = (member.size + 7) // 8

        type_name = member.type.dstr() if member.type else "unknown"

        field = FieldInfo(
            name=name,
            offset=byte_offset,
            size=byte_size,
            type_name=type_name,
            tinfo=ida_typeinf.tinfo_t(member.type),
        )

        if member.offset % 8 != 0 or member.size % 8 != 0:
            field.is_bitfield = True
            field.bit_offset = member.offset % 8
            field.bit_size = member.size

        if member.type and member.type.is_array():
            field.is_array = True
            field.array_size = member.type.get_array_nelems()
            field.elem_tinfo = member.type.get_array_element()

        fields.append(field)

    return fields


def is_union(tif: ida_typeinf.tinfo_t) -> bool:
    """Check if type is a union."""
    return tif.is_union()


def is_valid_ea(ea: int) -> bool:
    """Check if address is valid and readable."""
    if ea == ida_idaapi.BADADDR:
        return False
    return ida_segment.getseg(ea) is not None


def read_value_at(ea: int, size: int) -> int | None:
    """
    Read an integer value of given size at address.

    Returns None if read fails or crosses segment boundary.
    """
    if not is_valid_ea(ea):
        return None

    seg = ida_segment.getseg(ea)
    if seg is None:
        return None
    if ea + size > seg.end_ea:
        return None

    try:
        if size == 1:
            return ida_bytes.get_byte(ea)
        elif size == 2:
            return ida_bytes.get_word(ea)
        elif size == 4:
            return ida_bytes.get_dword(ea)
        elif size == 8:
            return ida_bytes.get_qword(ea)
        else:
            data = ida_bytes.get_bytes(ea, size)
            if data is None:
                return None
            return int.from_bytes(data, byteorder="little")
    except Exception:
        return None


def read_bytes_at(ea: int, size: int) -> bytes | None:
    """Read raw bytes at address with safety checks."""
    if not is_valid_ea(ea):
        return None

    seg = ida_segment.getseg(ea)
    if seg is None or ea + size > seg.end_ea:
        return None

    try:
        return ida_bytes.get_bytes(ea, size)
    except Exception:
        return None


def get_name_at(ea: int) -> str | None:
    """Get the name/label at an address if it exists."""
    if not is_valid_ea(ea):
        return None
    name = ida_name.get_name(ea)
    if name and not name.startswith("unk_") and not name.startswith("loc_"):
        return name
    return None


def format_integer_value(value: int, size: int) -> str:
    """Format an integer value with appropriate width."""
    width = size * 2
    return f"0x{value:0{width}X}"


def format_char_value(value: int) -> str:
    """Format a byte as character if printable."""
    if 0x20 <= value < 0x7F:
        return f" '{chr(value)}'"
    return ""


def format_float_value(value: int, size: int) -> str:
    """Format raw integer bytes as a floating-point value."""
    if size == 4:
        return f"{struct.unpack('f', struct.pack('I', value))[0]:g}"
    elif size == 8:
        return f"{struct.unpack('d', struct.pack('Q', value))[0]:g}"
    return format_integer_value(value, size)


def try_decode_ascii(data: bytes) -> str | None:
    """Try to decode bytes as a printable ASCII string (possibly null-terminated)."""
    stripped = data.rstrip(b"\x00")
    if not stripped:
        return None
    if all(0x20 <= b < 0x7F for b in stripped):
        return stripped.decode("ascii")
    return None


def format_pointer_value(value: int) -> str:
    """Format a pointer, including target name if known."""
    name = get_name_at(value)
    if name:
        return f"0x{value:X} ({name})"
    return f"0x{value:X}"


class GlobalStructDissectorHooks(idaapi.IDP_Hooks):
    """Hooks to intercept data rendering."""

    def _get_type_at(self, ea: int) -> ida_typeinf.tinfo_t | None:
        """
        Get structure type info at an address.

        Tries ida_nalt.get_tinfo first (set via 'Y' dialog / apply_tinfo),
        then falls back to detecting struct data applied via the Structures
        popup (which uses ida_bytes struct flags instead of tinfo).
        """
        tif = ida_typeinf.tinfo_t()
        if ida_nalt.get_tinfo(tif, ea):
            logger.debug("0x%X: tinfo = '%s' (via get_tinfo)", ea, tif.dstr())
            return tif

        flags = ida_bytes.get_flags(ea)
        if not ida_bytes.is_struct(flags):
            logger.debug("0x%X: no type info and not struct data", ea)
            return None

        oi = ida_nalt.opinfo_t()
        if not ida_bytes.get_opinfo(oi, ea, 0, flags):
            logger.debug("0x%X: struct flags set but get_opinfo failed", ea)
            return None

        tid = oi.tid
        if tid == ida_idaapi.BADADDR:
            logger.debug("0x%X: struct flags set but tid is BADADDR", ea)
            return None

        tif = ida_typeinf.tinfo_t()
        if not tif.get_type_by_tid(tid):
            logger.debug("0x%X: struct tid 0x%X but get_type_by_tid failed", ea, tid)
            return None

        logger.debug("0x%X: tinfo = '%s' (via struct flags, tid=0x%X)", ea, tif.dstr(), tid)
        return tif

    def _output_field_line(self, ctx, field: FieldInfo, base_ea: int, indent: int):
        """Output a single field with proper coloring."""
        prefix = " " * (indent * INDENT_SIZE)
        ea = base_ea + field.offset

        ctx.out_line(prefix)
        ctx.out_tagon(ida_lines.COLOR_NUMBER)
        ctx.out_line(f"+0x{field.offset:02X}:")
        ctx.out_tagoff(ida_lines.COLOR_NUMBER)
        ctx.out_line(" ")

        ctx.out_tagon(ida_lines.COLOR_DNAME)
        ctx.out_line(field.name)
        ctx.out_tagoff(ida_lines.COLOR_DNAME)

        ctx.out_tagon(ida_lines.COLOR_SYMBOL)
        ctx.out_line(" = ")
        ctx.out_tagoff(ida_lines.COLOR_SYMBOL)

        value = read_value_at(ea, field.size)
        if value is not None:
            if field.tinfo.is_ptr():
                ctx.out_tagon(ida_lines.COLOR_CREF)
                ctx.out_line(format_pointer_value(value))
                ctx.out_tagoff(ida_lines.COLOR_CREF)
            elif field.tinfo.is_floating():
                ctx.out_tagon(ida_lines.COLOR_NUMBER)
                ctx.out_line(format_float_value(value, field.size))
                ctx.out_tagoff(ida_lines.COLOR_NUMBER)
            else:
                ctx.out_tagon(ida_lines.COLOR_NUMBER)
                ctx.out_line(format_integer_value(value, field.size))
                ctx.out_tagoff(ida_lines.COLOR_NUMBER)
                if field.size == 1:
                    ctx.out_line(format_char_value(value))
        else:
            ctx.out_tagon(ida_lines.COLOR_ERROR)
            ctx.out_line("???")
            ctx.out_tagoff(ida_lines.COLOR_ERROR)

        ctx.flush_outbuf()

    def _output_struct(self, ctx, ea: int, tif: ida_typeinf.tinfo_t, indent: int = 0):
        """
        Output a complete structure with all fields.

        This is called recursively for nested structures.
        """
        prefix = " " * (indent * INDENT_SIZE)
        type_keyword = "union" if tif.is_union() else "struct"
        type_name = tif.dstr()

        ctx.out_line(prefix)
        ctx.out_keyword(type_keyword)
        ctx.out_line(" ")
        ctx.out_tagon(ida_lines.COLOR_KEYWORD)
        ctx.out_line(type_name)
        ctx.out_tagoff(ida_lines.COLOR_KEYWORD)
        ctx.out_line(" ")
        ctx.out_tagon(ida_lines.COLOR_SYMBOL)
        ctx.out_line("{")
        ctx.out_tagoff(ida_lines.COLOR_SYMBOL)
        ctx.flush_outbuf()

        if tif.is_union():
            ctx.out_line(prefix + "  ")
            ctx.out_tagon(ida_lines.COLOR_AUTOCMT)
            ctx.out_line("/* union - showing all interpretations */")
            ctx.out_tagoff(ida_lines.COLOR_AUTOCMT)
            ctx.flush_outbuf()

        fields = get_struct_fields(tif)

        if not fields:
            ctx.out_line(prefix + "  ")
            ctx.out_tagon(ida_lines.COLOR_AUTOCMT)
            ctx.out_line("/* empty structure */")
            ctx.out_tagoff(ida_lines.COLOR_AUTOCMT)
            ctx.flush_outbuf()
        else:
            for field in fields:
                field_ea = ea + field.offset

                if field.is_array and field.elem_tinfo:
                    elem_size = field.elem_tinfo.get_size()

                    if elem_size == 1:
                        raw = read_bytes_at(field_ea, field.array_size)
                        ascii_str = try_decode_ascii(raw) if raw else None
                        if ascii_str is not None:
                            inner_prefix = " " * ((indent + 1) * INDENT_SIZE)
                            ctx.out_line(inner_prefix)
                            ctx.out_tagon(ida_lines.COLOR_NUMBER)
                            ctx.out_line(f"+0x{field.offset:02X}:")
                            ctx.out_tagoff(ida_lines.COLOR_NUMBER)
                            ctx.out_line(" ")
                            ctx.out_tagon(ida_lines.COLOR_DNAME)
                            ctx.out_line(field.name)
                            ctx.out_tagoff(ida_lines.COLOR_DNAME)
                            ctx.out_tagon(ida_lines.COLOR_SYMBOL)
                            ctx.out_line(" = ")
                            ctx.out_tagoff(ida_lines.COLOR_SYMBOL)
                            ctx.out_tagon(ida_lines.COLOR_STRING)
                            ctx.out_line(f'"{ascii_str}"')
                            ctx.out_tagoff(ida_lines.COLOR_STRING)
                            ctx.flush_outbuf()
                            continue

                    for i in range(field.array_size):
                        elem_ea = field_ea + (i * elem_size)
                        elem_offset = field.offset + (i * elem_size)

                        if field.elem_tinfo.is_struct() or field.elem_tinfo.is_union():
                            inner_prefix = " " * ((indent + 1) * INDENT_SIZE)
                            ctx.out_line(inner_prefix)
                            ctx.out_tagon(ida_lines.COLOR_NUMBER)
                            ctx.out_line(f"+0x{elem_offset:02X}:")
                            ctx.out_tagoff(ida_lines.COLOR_NUMBER)
                            ctx.out_line(" ")
                            ctx.out_tagon(ida_lines.COLOR_DNAME)
                            ctx.out_line(f"{field.name}[{i}]")
                            ctx.out_tagoff(ida_lines.COLOR_DNAME)
                            ctx.out_tagon(ida_lines.COLOR_SYMBOL)
                            ctx.out_line(" = ")
                            ctx.out_tagoff(ida_lines.COLOR_SYMBOL)
                            ctx.flush_outbuf()
                            self._output_struct(ctx, elem_ea, field.elem_tinfo, indent + 2)
                        else:
                            inner_prefix = " " * ((indent + 1) * INDENT_SIZE)
                            ctx.out_line(inner_prefix)
                            ctx.out_tagon(ida_lines.COLOR_NUMBER)
                            ctx.out_line(f"+0x{elem_offset:02X}:")
                            ctx.out_tagoff(ida_lines.COLOR_NUMBER)
                            ctx.out_line(" ")
                            ctx.out_tagon(ida_lines.COLOR_DNAME)
                            ctx.out_line(f"{field.name}[{i}]")
                            ctx.out_tagoff(ida_lines.COLOR_DNAME)
                            ctx.out_tagon(ida_lines.COLOR_SYMBOL)
                            ctx.out_line(" = ")
                            ctx.out_tagoff(ida_lines.COLOR_SYMBOL)

                            value = read_value_at(elem_ea, elem_size)
                            if value is not None:
                                ctx.out_tagon(ida_lines.COLOR_NUMBER)
                                ctx.out_line(format_integer_value(value, elem_size))
                                ctx.out_tagoff(ida_lines.COLOR_NUMBER)
                                if elem_size == 1:
                                    ctx.out_line(format_char_value(value))
                            else:
                                ctx.out_tagon(ida_lines.COLOR_ERROR)
                                ctx.out_line("???")
                                ctx.out_tagoff(ida_lines.COLOR_ERROR)
                            ctx.flush_outbuf()

                elif field.tinfo.is_struct() or field.tinfo.is_union():
                    inner_prefix = " " * ((indent + 1) * INDENT_SIZE)
                    ctx.out_line(inner_prefix)
                    ctx.out_tagon(ida_lines.COLOR_NUMBER)
                    ctx.out_line(f"+0x{field.offset:02X}:")
                    ctx.out_tagoff(ida_lines.COLOR_NUMBER)
                    ctx.out_line(" ")
                    ctx.out_tagon(ida_lines.COLOR_DNAME)
                    ctx.out_line(field.name)
                    ctx.out_tagoff(ida_lines.COLOR_DNAME)
                    ctx.out_tagon(ida_lines.COLOR_SYMBOL)
                    ctx.out_line(" = ")
                    ctx.out_tagoff(ida_lines.COLOR_SYMBOL)
                    ctx.flush_outbuf()
                    self._output_struct(ctx, field_ea, field.tinfo, indent + 2)

                elif field.is_bitfield:
                    inner_prefix = " " * ((indent + 1) * INDENT_SIZE)
                    bit_hi = field.bit_offset + field.bit_size - 1
                    bit_lo = field.bit_offset

                    ctx.out_line(inner_prefix)
                    ctx.out_tagon(ida_lines.COLOR_NUMBER)
                    ctx.out_line(f"+0x{field.offset:02X}[{bit_hi}:{bit_lo}]:")
                    ctx.out_tagoff(ida_lines.COLOR_NUMBER)
                    ctx.out_line(" ")
                    ctx.out_tagon(ida_lines.COLOR_DNAME)
                    ctx.out_line(field.name)
                    ctx.out_tagoff(ida_lines.COLOR_DNAME)
                    ctx.out_tagon(ida_lines.COLOR_SYMBOL)
                    ctx.out_line(" = ")
                    ctx.out_tagoff(ida_lines.COLOR_SYMBOL)

                    container_size = (field.bit_size + field.bit_offset + 7) // 8
                    container_value = read_value_at(ea + field.offset, container_size)
                    if container_value is not None:
                        mask = (1 << field.bit_size) - 1
                        value = (container_value >> field.bit_offset) & mask
                        ctx.out_tagon(ida_lines.COLOR_NUMBER)
                        ctx.out_line(f"0x{value:X}")
                        ctx.out_tagoff(ida_lines.COLOR_NUMBER)
                    else:
                        ctx.out_tagon(ida_lines.COLOR_ERROR)
                        ctx.out_line("???")
                        ctx.out_tagoff(ida_lines.COLOR_ERROR)
                    ctx.flush_outbuf()

                else:
                    self._output_field_line(ctx, field, ea, indent + 1)

        ctx.out_line(prefix)
        ctx.out_tagon(ida_lines.COLOR_SYMBOL)
        ctx.out_line("}")
        ctx.out_tagoff(ida_lines.COLOR_SYMBOL)
        ctx.flush_outbuf()

    def ev_out_data(self, ctx, analyze_only):
        """
        Called when IDA wants to output a data item.

        CRITICAL: We must emit the SAME output for both analyze_only=True and
        analyze_only=False passes, otherwise IDA will measure incorrectly and
        produce garbled/clipped output.

        Args:
            ctx: outctx_t - output context
            analyze_only: bool - if True, measuring; if False, rendering

        Returns:
            1 if we handled the output, 0 to let IDA handle it
        """
        ea = ctx.insn_ea
        logger.debug("ev_out_data called: ea=0x%X analyze_only=%s", ea, analyze_only)

        if not is_global_data_segment(ea):
            return 0

        tif = self._get_type_at(ea)
        if tif is None:
            return 0

        item_size = ida_bytes.get_item_size(ea)
        type_size = tif.get_size()
        if item_size != type_size:
            logger.debug(
                "0x%X: item size %d != type size %d for '%s', skipping (data type changed?)",
                ea, item_size, type_size, tif.dstr(),
            )
            return 0

        unwrapped = unwrap_type(tif)
        if unwrapped is None:
            logger.debug("0x%X: type '%s' is not a struct/union (after unwrap)", ea, tif.dstr())
            return 0

        logger.debug(
            "0x%X: dissecting struct '%s' (array=%s, count=%d)",
            ea, unwrapped.tinfo.dstr(), unwrapped.is_array, unwrapped.array_count,
        )

        try:
            if unwrapped.is_array:
                struct_size = unwrapped.tinfo.get_size()
                for i in range(unwrapped.array_count):
                    elem_ea = ea + (i * struct_size)
                    ctx.out_tagon(ida_lines.COLOR_AUTOCMT)
                    ctx.out_line(f"/* [{i}] */")
                    ctx.out_tagoff(ida_lines.COLOR_AUTOCMT)
                    ctx.flush_outbuf()
                    self._output_struct(ctx, elem_ea, unwrapped.tinfo, indent=0)
            else:
                self._output_struct(ctx, ea, unwrapped.tinfo, indent=0)

            logger.debug("0x%X: dissection complete, returning 1", ea)
            return 1

        except Exception as e:
            logger.exception("Error formatting structure at 0x%X: %s", ea, e)
            return 0


class global_struct_dissector_plugmod_t(ida_idaapi.plugmod_t):
    """Plugin module - handles lifecycle."""

    def __init__(self):
        super().__init__()
        self.hooks: GlobalStructDissectorHooks | None = None
        self.init()

    def init(self):
        """Initialize the plugin."""
        if not ida_auto.auto_is_ok():
            logger.debug("Waiting for auto-analysis to complete")
            ida_auto.auto_wait()

        self.register_hooks()
        logger.info("Global Struct Dissector plugin loaded (set logging to DEBUG for diagnostics)")

    def register_hooks(self):
        """Register IDP hooks."""
        self.hooks = GlobalStructDissectorHooks()
        ok = self.hooks.hook()
        if ok:
            logger.debug("IDP hooks registered")
        else:
            logger.warning("IDP hooks registration FAILED")

    def unregister_hooks(self):
        """Unregister IDP hooks."""
        if self.hooks:
            self.hooks.unhook()
            self.hooks = None
            logger.debug("IDP hooks unregistered")

    def run(self, arg):
        """Called when user selects plugin from menu."""
        logger.info("Global Struct Dissector is active")

    def term(self):
        """Cleanup on plugin unload."""
        self.unregister_hooks()
        logger.info("Global Struct Dissector plugin unloaded")


class global_struct_dissector_plugin_t(ida_idaapi.plugin_t):
    """Plugin entry point."""

    flags = ida_idaapi.PLUGIN_MULTI
    help = "Format structure instances with explicit field names and offsets"
    comment = "Better structure rendering in disassembly"
    wanted_name = "Global Struct Dissector"
    wanted_hotkey = ""

    def init(self):
        return global_struct_dissector_plugmod_t()
