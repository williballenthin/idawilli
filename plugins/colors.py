import ctypes
import functools

import idaapi
import ida_ua
import ida_funcs
import ida_frame
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


def mainthread(function):
    """
    A function decorator to ensure the function executes on the main IDA thread.
    via: https://github.com/gaasedelen/lighthouse/blob/f4642e8b4b4347b11ccb25a79ec4f490c9ad901d/plugins/lighthouse/painting/ida_painter.py#L70
    """
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        ff = functools.partial(function, *args, **kwargs)
        return idaapi.execute_sync(ff, idaapi.MFF_NOWAIT | idaapi.MFF_WRITE)
    return wrapper


# the only way to install this is by instantiating an instance *from within a plugin*.
class CallPrefix(ida_lines.user_defined_prefix_t):
    def __init__(self):
        super().__init__(len(">>>"))

    def get_user_defined_prefix(self, ea, insn, lnnum, indent, line):
        mnem = insn.get_canon_mnem()

        if mnem == "call":
            return ">>>"

        #elif mnem == "push":
        #    return "-->"

        else:
            return "   "


class ColorsPlugin(ida_idaapi.plugin_t):
    flags = 0
    comment = "Colors"
    help = ""
    wanted_name = "Colors"
    wanted_hotkey = ""

    def __init__(self):
        self.prefix = None
        self.hooks = ColorHooks()

    def init(self):
        self.prefix = CallPrefix()
        self.hooks.hook()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        self.prefix = None
        self.hooks.unhook()


def PLUGIN_ENTRY():
    return ColorsPlugin()
