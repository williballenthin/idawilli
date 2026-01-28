import logging

import ida_kernwin


logger = logging.getLogger(__name__)

oplog_ok = True

if oplog_ok:
    kernel_version: tuple[int, ...] = tuple(int(part) for part in ida_kernwin.get_kernel_version().split(".") if part.isdigit()) or (0, )
    if kernel_version < (9, 2):  # type: ignore
        logger.warning("IDA too old (must be 9.2+): %s", ida_kernwin.get_kernel_version())
        oplog_ok = False


if oplog_ok:
    # only attempt to import oplog once we know the required dependencies are present.
    # otherwise we'll hit ImportError and other problems
    from oplog import oplog_plugin_t

    def PLUGIN_ENTRY():
        return oplog_plugin_t()

else:
    try:
        import ida_idaapi
    except ImportError:
        import idaapi as ida_idaapi

    class nop_plugin_t(ida_idaapi.plugin_t):
        flags = ida_idaapi.PLUGIN_HIDE | ida_idaapi.PLUGIN_UNL
        wanted_name = "oplog disabled"
        comment = "oplog is disabled for this IDA version"
        help = ""
        wanted_hotkey = ""

        def init(self):
            return ida_idaapi.PLUGIN_SKIP
    
    # we have to define this symbol, or IDA logs a message
    def PLUGIN_ENTRY():
        # we have to return something here, or IDA logs a message
        return nop_plugin_t()
