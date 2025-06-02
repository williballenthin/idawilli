import idaapi
import multifile_ida_plugin


class multifile_plugmod_t(idaapi.plugmod_t):
    def run(self, arg):
        multifile_ida_plugin.hello()
        return 0


class multifile_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL | idaapi.PLUGIN_MULTI
    comment = "This is an example Python plugin (multifile) (comment)"
    help = "This is an example Python plugin (multifile)"
    wanted_name = "Example Python plugin (multifile)"
    wanted_hotkey = ""

    def init(self):
        return multifile_plugmod_t()


def PLUGIN_ENTRY():
    return multifile_plugin_t()
