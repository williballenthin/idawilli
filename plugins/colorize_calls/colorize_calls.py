import ctypes

import idaapi
import ida_ua
import ida_lines
import ida_idaapi


class ColorHooks(idaapi.IDP_Hooks):
    def ev_get_bg_color(self, color, ea):
        """
        Get item background color.
        Plugins can hook this callback to color disassembly lines dynamically

        ```c
        // background color in RGB
        typedef uint32 bgcolor_t;
        ```
        ref: https://hex-rays.com/products/ida/support/sdkdoc/pro_8h.html#a3df5040891132e50157aee66affdf1de

        args:
            color: (bgcolor_t *), out
            ea: (::ea_t)

        returns:
            retval 0: not implemented
            retval 1: color set
        """
        mnem = ida_ua.print_insn_mnem(ea)

        if mnem == "call":
            bgcolor = ctypes.cast(int(color), ctypes.POINTER(ctypes.c_int))
            # TODO: make this configurable
            bgcolor[0] = 0xDDDDDD
            return 1

        else:
            return 0

    def ev_out_mnem(self, ctx) -> int:
        """
        Generate instruction mnemonics.
        This callback should append the colored mnemonics to ctx.outbuf 
        Optional notification, if absent, out_mnem will be called.

        args:
            ctx: (outctx_t *)

        returns:
            retval 1: if appended the mnemonics
            retval 0: not implemented
        """
        mnem = ctx.insn.get_canon_mnem()
        if mnem == "call":
            # you can manipulate this, but note that it affects `ida_ua.print_insn_mnem` which is inconvenient for formatting.
            # also, you only have access to theme colors, like COLOR_PREFIX, not arbitrary control.
            ctx.out_custom_mnem("call")
            return 1

        else:
            return 0


# the only way to install this is by instantiating an instance *from within a plugin*.
class CallPrefix(ida_lines.user_defined_prefix_t):
    def __init__(self):
        super().__init__(len(">>>"))

    def get_user_defined_prefix(self, ea, insn, lnnum, indent, line):
        mnem = insn.get_canon_mnem()

        if mnem == "call":
            return ">>>"

        else:
            return "   "


class ColorizeCallsPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_MULTI
    comment = "Colorize call instructions and add a prefix"
    help = "Colorize call instructions and add a prefix"
    wanted_name = "Colorize Calls"
    wanted_hotkey = ""

    def __init__(self):
        self.prefix = None
        self.hooks = ColorHooks()

    def init(self):
        self.prefix = CallPrefix()
        self.hooks.hook()
        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        self.prefix = None
        self.hooks.unhook()


def PLUGIN_ENTRY():
    return ColorizeCallsPlugin()
