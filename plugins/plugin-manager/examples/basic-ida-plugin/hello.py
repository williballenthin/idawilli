import idaapi


class hello_plugmod_t(idaapi.plugmod_t):
    def run(self, arg):
        print("Hello world from Python!")
        return 0


class hello_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL | idaapi.PLUGIN_MULTI
    comment = "This is an example Python plugin (comment)"
    help = "This is an example Python plugin"
    wanted_name = "Example Python plugin"
    wanted_hotkey = ""

    def init(self):
        return hello_plugmod_t()


def PLUGIN_ENTRY():
    return hello_plugin_t()
