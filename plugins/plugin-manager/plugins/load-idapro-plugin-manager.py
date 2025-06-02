import idaapi

import idapro_plugin_manager


class loader_plugin_t(idaapi.plugin_t):
    # don't use PLUGIN_FIX because we want plugins to be re-loaded at various lifecycle points, not just at startup.
    flags = idaapi.PLUGIN_MULTI | idaapi.PLUGIN_HIDE
    comment = "Plugin used to load other plugins"
    help = "Plugin used to load other plugins"
    wanted_name = "IDA Pro Plugin Manager Loader"
    wanted_hotkey = ""

    def init(self):
        idapro_plugin_manager.install()


def PLUGIN_ENTRY():
    return loader_plugin_t()
