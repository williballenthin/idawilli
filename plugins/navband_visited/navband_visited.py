import logging

import idaapi
import ida_bytes
import ida_kernwin


logger = logging.getLogger(__name__)


class NavbandHooks(ida_kernwin.UI_Hooks):
    def __init__(self):
        super().__init__()
        self.addresses = set()
        self.orig_colorizer = None

    def screen_ea_changed(self, ea, _prev_ea):
        if ea == idaapi.BADADDR:
            return

        item_size = ida_bytes.get_item_size(ea)
        if item_size == 0:
            # if not an item head or unexplored, mark at least one byte
            item_size = 1

        for i in range(item_size):
            self.addresses.add(ea + i)

    def colorizer(self, ea, nbytes):
        if ea in self.addresses:
            return 0x000000  # black

        if self.orig_colorizer:
            return ida_kernwin.call_nav_colorizer(self.orig_colorizer, ea, nbytes)

        return None

    def activate(self):
        self.hook()
        self.orig_colorizer = ida_kernwin.set_nav_colorizer(self.colorizer)
        logger.debug("hooks activated")

    def deactivate(self):
        if self.orig_colorizer is not None:
            ida_kernwin.set_nav_colorizer(self.orig_colorizer)
            self.orig_colorizer = None

        self.unhook()
        logger.debug("hooks deactivated")


class NavbandVisitedPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP | idaapi.PLUGIN_MULTI
    comment = "Tracks and records all visited addresses, showing in the navband"
    help = "This plugin records all the addresses you visit during your analysis, showing the visited addresses in the navband"
    wanted_name = "Navband Visited Indicator"
    wanted_hotkey = ""

    def __init__(self):
        super().__init__()
        self.hooks_manager = None

    def init(self):
        self.hooks_manager = NavbandHooks()
        self.hooks_manager.activate()
        return idaapi.PLUGIN_KEEP

    def term(self):
        if self.hooks_manager:
            self.hooks_manager.deactivate()
            self.hooks_manager = None


def PLUGIN_ENTRY():
    return NavbandVisitedPlugin()
