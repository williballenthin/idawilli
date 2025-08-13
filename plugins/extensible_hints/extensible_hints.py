'''
example of:
  - providing custom UI hints with dynamic data triggered by icons in the line prefix

Author: Willi Ballenthin <william.ballenthin@fireeye.com>
Licence: Apache 2.0
'''
import sys
import datetime

import idc
import idaapi
import idautils
import ida_ua
import ida_lines

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




# the only way to install this is by instantiating an instance *from within a plugin*.
class Prefixer(ida_lines.user_defined_prefix_t):
    def __init__(self):
        super().__init__(3)

    def get_user_defined_prefix(self, ea, insn, lnnum, indent, line):
        mnem = ida_ua.print_insn_mnem(ea)

        if mnem == "call":
            return ida_lines.COLSTR(" ☼ ", ida_lines.SCOLOR_SYMBOL)
        else:
            return "   "


class HintsHooks(idaapi.UI_Hooks):
    def get_custom_viewer_hint(self, view, place):
        curline = idaapi.get_custom_viewer_curline(view, True)
        _, x, y = idaapi.get_custom_viewer_place(view, True)

        token = get_token_at_char(curline, x)
        if token == " ☼ ":
            return ("<MSDN documentation here>", 1)

    def get_ea_hint(self, ea):
        return datetime.datetime.now().isoformat(' ')


class DynHints2Plugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Display dynamically-generated hints (3)."

    help = "Display dynamically-generated hints (3)."
    wanted_name = "extensible hints"
    wanted_hotkey = ""

    def __init__(self):
        self.prefix = None

    def init(self):
        # self.prefix = Prefixer()
        self.hooks = HintsHooks()
        return idaapi.PLUGIN_OK

    def run(self, arg):
        print('hints3: run')
        self.hooks.hook()
        self.prefix = Prefixer()

    def term(self):
        print('hints3: term')
        self.hooks.unhook()
        self.prefix = None


def PLUGIN_ENTRY():
    return DynHints2Plugin()
