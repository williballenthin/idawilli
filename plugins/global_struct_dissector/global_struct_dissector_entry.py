import logging
import os

import ida_kernwin

logger = logging.getLogger(__name__)


def should_load():
    if not ida_kernwin.is_idaq():
        return False

    if os.environ.get("IDA_IS_INTERACTIVE") != "1":
        return False

    kernel_version: tuple[int, ...] = tuple(
        int(part) for part in ida_kernwin.get_kernel_version().split(".") if part.isdigit()
    ) or (0,)
    if kernel_version < (9, 2):
        logger.warning("IDA too old (must be 9.2+): %s", ida_kernwin.get_kernel_version())
        return False

    return True


if should_load():
    from global_struct_dissector import global_struct_dissector_plugin_t

    def PLUGIN_ENTRY():
        return global_struct_dissector_plugin_t()

else:
    try:
        import ida_idaapi
    except ImportError:
        import idaapi as ida_idaapi

    class gsd_nop_plugin_t(ida_idaapi.plugin_t):
        flags = ida_idaapi.PLUGIN_HIDE | ida_idaapi.PLUGIN_UNL
        wanted_name = "global-struct-dissector disabled"
        comment = "global-struct-dissector is disabled for this IDA version"
        help = ""
        wanted_hotkey = ""

        def init(self):
            return ida_idaapi.PLUGIN_SKIP

    def PLUGIN_ENTRY():
        return gsd_nop_plugin_t()
