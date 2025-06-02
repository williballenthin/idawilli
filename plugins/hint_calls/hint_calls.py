"""
IDA plugin to display the calls and strings referenced by a function as hints.

Installation: put this file in your %IDADIR%/plugins/ directory.
Author: Willi Ballenthin <william.ballenthin@fireeye.com>
Licence: Apache 2.0
"""

import re
import logging
from typing import Optional

import idc
import idaapi
import ida_nalt
import ida_xref
import idautils
import ida_bytes
import ida_lines
import ida_kernwin

logger = logging.getLogger(__name__)
DEFAULT_IMPORTANT_LINES_NUM = 5


###############################################################################
#### begin: idapython_lex_curline
# via: https://gist.github.com/williballenthin/466eb28679d30e212ffac57e4a9ceaa5
# note: inline here for simplicity


# inverse mapping of color value to name.
# ref: https://www.hex-rays.com/products/ida/support/sdkdoc/group___s_c_o_l_o_r__.html#ga6052470f86411b8b5ffdf4af4bbee225
INV_COLORS = {
    0x1: "COLOR_DEFAULT",  #    = 0x01,         // Default
    0x2: "COLOR_REGCMT",  #     = 0x02,         // Regular comment
    0x3: "COLOR_RPTCMT",  #     = 0x03,         // Repeatable comment (comment defined somewhere else)
    0x4: "COLOR_AUTOCMT",  #    = 0x04,         // Automatic comment
    0x5: "COLOR_INSN",  #       = 0x05,         // Instruction
    0x6: "COLOR_DATNAME",  #    = 0x06,         // Dummy Data Name
    0x7: "COLOR_DNAME",  #      = 0x07,         // Regular Data Name
    0x8: "COLOR_DEMNAME",  #    = 0x08,         // Demangled Name
    0x9: "COLOR_SYMBOL",  #     = 0x09,         // Punctuation
    0xA: "COLOR_CHAR",  #       = 0x0A,         // Char constant in instruction
    0xB: "COLOR_STRING",  #     = 0x0B,         // String constant in instruction
    0xC: "COLOR_NUMBER",  #     = 0x0C,         // Numeric constant in instruction
    0xD: "COLOR_VOIDOP",  #     = 0x0D,         // Void operand
    0xE: "COLOR_CREF",  #       = 0x0E,         // Code reference
    0xF: "COLOR_DREF",  #       = 0x0F,         // Data reference
    0x10: "COLOR_CREFTAIL",  #  = 0x10,         // Code reference to tail byte
    0x11: "COLOR_DREFTAIL",  #  = 0x11,         // Data reference to tail byte
    0x12: "COLOR_ERROR",  #     = 0x12,         // Error or problem
    0x13: "COLOR_PREFIX",  #    = 0x13,         // Line prefix
    0x14: "COLOR_BINPREF",  #   = 0x14,         // Binary line prefix bytes
    0x15: "COLOR_EXTRA",  #     = 0x15,         // Extra line
    0x16: "COLOR_ALTOP",  #     = 0x16,         // Alternative operand
    0x17: "COLOR_HIDNAME",  #   = 0x17,         // Hidden name
    0x18: "COLOR_LIBNAME",  #   = 0x18,         // Library function name
    0x19: "COLOR_LOCNAME",  #   = 0x19,         // Local variable name
    0x1A: "COLOR_CODNAME",  #   = 0x1A,         // Dummy code name
    0x1B: "COLOR_ASMDIR",  #    = 0x1B,         // Assembler directive
    0x1C: "COLOR_MACRO",  #     = 0x1C,         // Macro
    0x1D: "COLOR_DSTR",  #      = 0x1D,         // String constant in data directive
    0x1E: "COLOR_DCHAR",  #     = 0x1E,         // Char constant in data directive
    0x1F: "COLOR_DNUM",  #      = 0x1F,         // Numeric constant in data directive
    0x20: "COLOR_KEYWORD",  #   = 0x20,         // Keywords
    0x21: "COLOR_REG",  #       = 0x21,         // Register name
    0x22: "COLOR_IMPNAME",  #   = 0x22,         // Imported name
    0x23: "COLOR_SEGNAME",  #   = 0x23,         // Segment name
    0x24: "COLOR_UNKNAME",  #   = 0x24,         // Dummy unknown name
    0x25: "COLOR_CNAME",  #     = 0x25,         // Regular code name
    0x26: "COLOR_UNAME",  #     = 0x26,         // Regular unknown name
    0x27: "COLOR_COLLAPSED",  # = 0x27,         // Collapsed line
    #  // Fictive colors
    0x28: "COLOR_ADDR",  #      = 0x28,         // hidden address marks
    #        // The address is represented as 8digit
    #        // hex number: 01234567
    #        // It doesn"t have COLOR_OFF pair
    #        // NB: for 64-bit IDA, the address is 16digit
    0x29: "COLOR_OPND1",  # = COLOR_ADDR+1, // Instruction operand 1
    0x2A: "COLOR_OPND2",  # = COLOR_ADDR+2, // Instruction operand 2
    0x2B: "COLOR_OPND3",  # = COLOR_ADDR+3, // Instruction operand 3
    0x2C: "COLOR_OPND4",  # = COLOR_ADDR+4, // Instruction operand 4
    0x2D: "COLOR_OPND5",  # = COLOR_ADDR+5, // Instruction operand 5
    0x2E: "COLOR_OPND6",  # = COLOR_ADDR+6, // Instruction operand 6
    0x32: "COLOR_UTF8",  #  = COLOR_ADDR+10;// Following text is UTF-8 encoded
}


class Symbol(object):
    def __init__(self, type):
        super(Symbol, self).__init__()
        self.type = type

    def __str__(self):
        raise NotImplementedError()


class StringSymbol(Symbol):
    def __init__(self, string):
        super(StringSymbol, self).__init__("string")
        self.string = string

    def __str__(self):
        return "STRING=" + self.string


class ColorOnSymbol(Symbol):
    def __init__(self, color):
        super(ColorOnSymbol, self).__init__("coloron")
        self.color = ord(color)

    def __str__(self):
        return "COLORON=" + INV_COLORS[self.color]


class ColorOffSymbol(Symbol):
    def __init__(self, color):
        super(ColorOffSymbol, self).__init__("coloroff")
        self.color = ord(color)

    def __str__(self):
        return "COLOROFF=" + INV_COLORS[self.color]


class ColorInvSymbol(Symbol):
    def __init__(self):
        super(ColorInvSymbol, self).__init__("colorinv")

    def __str__(self):
        return "COLORINV"


def lex(curline):
    """
    split the line returned by `get_custom_viewer_curline` into symbols.
    it pulls out the strings, color directives, and escaped characters.

    Args:
      curline (str): a line returned by `ida_kernwin.get_custom_viewer_curline`

    Returns:
      generator: generator of Symbol subclass instances
    """

    offset = 0
    cur_word: list[str] = []
    while offset < len(curline):

        c = curline[offset]

        if c == ida_lines.COLOR_ON:
            if cur_word:
                yield StringSymbol("".join(cur_word))
                cur_word = []

            offset += 1
            color = curline[offset]

            yield ColorOnSymbol(color)
            offset += 1

        elif c == ida_lines.COLOR_OFF:
            if cur_word:
                yield StringSymbol("".join(cur_word))
                cur_word = []

            offset += 1
            color = curline[offset]

            yield ColorOffSymbol(color)
            offset += 1

        elif c == ida_lines.COLOR_ESC:
            if cur_word:
                yield StringSymbol("".join(cur_word))
                cur_word = []

            offset += 1
            c = curline[offset]

            cur_word.append(c)
            offset += 1

        elif c == ida_lines.COLOR_INV:
            if cur_word:
                yield StringSymbol("".join(cur_word))
                cur_word = []

            yield ColorInvSymbol()
            offset += 1

        else:
            cur_word.append(c)
            offset += 1


def get_color_at_char(curline, index):
    curlen = 0
    curcolor = 0
    for sym in lex(curline):
        if sym.type == "string":
            curlen += len(sym.string)
            if curlen >= index:
                return curcolor
        elif sym.type == "coloron":
            curcolor = sym.color
        elif sym.type == "coloroff":
            curcolor = 0
        else:
            curcolor = 0

    return curcolor


def get_token_at_char(curline, index):
    curlen = 0
    for sym in lex(curline):
        if sym.type == "string":
            curlen += len(sym.string)
            if curlen >= index:
                return sym.string
        else:
            continue

    return ""


#### end: idapython_lex_curline
###############################################################################


def enum_function_addrs(fva):
    """
    yield the effective addresses of each instruction in the given function.
    these addresses are not guaranteed to be in any order.

    Args:
      fva (int): the starting address of a function

    Returns:
      sequence[int]: the addresses of each instruction
    """
    f = idaapi.get_func(fva)
    if not f:
        raise ValueError("not a function")

    for block in idaapi.FlowChart(f):
        ea = block.start_ea
        while ea <= block.end_ea:
            yield ea
            ea = ida_bytes.next_head(ea, idc.BADADDR)


def enum_calls_in_function(fva):
    """
    yield the call instructions in the given function.

    Args:
      fva (int): the starting address of a function

    Returns:
      sequence[tuple[int, str]]: the address of a call instruction, and the disassembly line at that address
    """
    for ea in enum_function_addrs(fva):
        if idaapi.is_call_insn(ea):
            disasm = ida_lines.generate_disassembly(ea, 16, True, False)[1][0]
            # replace consequent whitespaces by a single whitespaces
            disasm = re.sub(r"\s\s+", " ", disasm)
            yield ea, disasm


def enum_string_refs_in_function(fva):
    """
    yield the string references in the given function.

    Args:
      fva (int): the starting address of a function

    Returns:
      sequence[tuple[int, int, str]]: tuples of metadata, including:
       - the address of the instruction referencing a string
       - the address of the string
       - the string
    """
    for ea in enum_function_addrs(fva):
        for ref in idautils.DataRefsFrom(ea):
            stype = ida_nalt.get_str_type(ref)
            if stype < 0 or stype > 7:
                continue

            CALC_MAX_LEN = -1
            try:
                s = ida_bytes.get_strlit_contents(ref, CALC_MAX_LEN, stype).decode("utf-8")
            except UnicodeDecodeError:
                s = str(ida_bytes.get_strlit_contents(ref, CALC_MAX_LEN, stype))

            yield ea, ref, s


def uniq(s):
    """
    yield the unique items in the given sequence.
    only provide the first copy encountered, skipping subsequent copies.

    Args:
      s (sequence[T]): a sequence of things

    Returns:
      sequence[T]: a sequence of the unique copies
    """
    seen = set([])

    for item in s:
        if item in seen:
            continue

        yield item

        seen.add(item)


def render_function_hint(fva):
    """
    create a textual report for the call and string references in the given function.

    eg.

        3 calls, 4 strings

        calls:
          - call     new
          - call     gethostbyname
          - call     delete

        strings:
          - www.google.com
          - www.bing.com
          - www.yahoo.com
          - www.cnn.com

    Args:
      fva (int): the starting address of a function

    Returns:
      str: the report
    """
    ret = []

    # use `uniq` here (vs using a set) cause we want to maintain *some* semblance of order.
    calls = list(uniq(d for f, d in enum_calls_in_function(fva)))
    strings = list(uniq(s for o, r, s in enum_string_refs_in_function(fva)))
    xrefs = [
        xref.frm
        for xref in idautils.XrefsTo(fva, ida_xref.XREF_ALL)
        if ida_bytes.is_code(ida_bytes.get_flags(xref.frm))
    ]

    # this would be a good place to use Jinja2 templating,
    #  but lets not require that external dependency
    title = ida_lines.COLSTR("%d calls, " % len(calls), ida_lines.SCOLOR_CODNAME)
    title += ida_lines.COLSTR("%s strings, " % len(strings), ida_lines.SCOLOR_DSTR)
    title += ida_lines.COLSTR("%d xrefs " % len(xrefs), ida_lines.SCOLOR_DEFAULT)
    ret.append(title)

    ret.append("")
    if calls:
        ret.append(ida_lines.COLSTR("calls:", ida_lines.SCOLOR_DEFAULT))
        for call in calls:
            ret.append("  - " + call)
        ret.append("")

    if strings:
        ret.append(ida_lines.COLSTR("strings:", ida_lines.SCOLOR_DEFAULT))
        for s in strings:
            ret.append('  - "' + ida_lines.COLSTR(s, ida_lines.SCOLOR_DSTR) + '"')

    return "\n".join(ret)


class CallsHintsHook(ida_kernwin.UI_Hooks):
    def get_custom_viewer_hint(self, view, place: Optional[ida_kernwin.place_t]):
        if not place:
            return None

        try:
            widget = ida_kernwin.get_current_widget()
            if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_DISASM:
                return None

            curline = ida_kernwin.get_custom_viewer_curline(view, True)

            # sometimes get_custom_viewer_place() returns [x, y] and sometimes [place_t, x, y].
            # we want the place_t.
            viewer_place = ida_kernwin.get_custom_viewer_place(view, True)
            if len(viewer_place) != 3:
                return None

            _, x, _y = viewer_place
            ea = place.toea()

            # "color" is a bit of misnomer: its the type of the symbol currently hinted
            color = get_color_at_char(curline, x)
            if color != ida_lines.COLOR_ADDR:
                return None

            # grab the FAR references to code (not necessarilty a branch/call/jump by itself)
            far_code_references = [
                xref.to
                for xref in idautils.XrefsFrom(ea, ida_xref.XREF_FAR)
                if ida_bytes.is_code(ida_bytes.get_flags(xref.to))
            ]
            if len(far_code_references) != 1:
                return None

            fva = far_code_references[0]

            # ensure its actually a function
            if not idaapi.get_func(fva):
                return None

            # this magic constant is the number of "important lines" to display by default.
            # the remaining lines get shown if you scroll down while the hint is displayed, revealing more lines.
            return render_function_hint(fva), DEFAULT_IMPORTANT_LINES_NUM
        except Exception as e:
            logger.warning("unexpected exception: %s. Get in touch with @williballenthin.", e, exc_info=True)
            return None


class CallsHintsPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP | idaapi.PLUGIN_HIDE
    comment = "Display the calls and strings referenced by a function as hints."
    help = "Display the calls and strings referenced by a function as hints."
    wanted_name = "Hint Calls Plugin"
    wanted_hotkey = ""

    def __init__(self):
        super().__init__()
        self.hooks: CallsHintsHook | None = None

    def init(self):
        self.hooks = CallsHintsHook()
        if self.hooks.hook():
            return idaapi.PLUGIN_KEEP
        else:
            logger.warning("error setting hooks.")
            return idaapi.PLUGIN_SKIP

    def term(self):
        if self.hooks:
            self.hooks.unhook()
            self.hooks = None


def PLUGIN_ENTRY():
    return CallsHintsPlugin()
