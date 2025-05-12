import idaapi
import ida_bytes
import ida_kernwin


class navband_visited_plugmod_t(idaapi.plugmod_t, ida_kernwin.UI_Hooks):
    def __init__(self):
        super().__init__()
        self.addresses = set()
        self.orig_colorizer = None

    def screen_ea_changed(self, ea, prev_ea):
        if ea == idaapi.BADADDR:
            return

        for i in range(ea, ea + ida_bytes.get_item_size(ea)):
            self.addresses.add(i)

    def colorizer(self, ea, nbytes):
        # when we've visited the address, color it black
        if ea in self.addresses:
            return 0x000000  # black

        # otherwise, show the original colors
        return ida_kernwin.call_nav_colorizer(self.orig_colorizer, ea, nbytes)

    def run(self, arg):
        self.hook()
        self.orig_colorizer = ida_kernwin.set_nav_colorizer(self.colorizer)

    def term(self):
        self.unhook()
        idaapi.set_nav_colorizer(self.orig_colorizer)


class navband_visited_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_MULTI
    comment = "Tracks and records all visited addresses, showing in the navband"
    help = "This plugin records all the addresses you visit during your analysis, showing the visited addresses in the navband"
    wanted_name = "Navband visited"
    wanted_hotkey = ""

    def init(self):
        return navband_visited_plugmod_t()


def PLUGIN_ENTRY():
    return navband_visited_plugin_t()
