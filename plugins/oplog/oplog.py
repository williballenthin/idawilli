import logging

import ida_idaapi

from .oplog_hooks import IDBChangedHook

logger = logging.getLogger(__name__)


class OplogPluginMod(ida_idaapi.plugmod_t):
    def __init__(self):
        self.idb_hooks: IDBChangedHook | None = None

    def run(self, arg):
        self.idb_hooks = IDBChangedHook()

        self.idb_hooks.hook()

    def term(self):
        if self.idb_hooks is not None:
            self.idb_hooks.unhook()


class OplogPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    help = "Log activity in the current IDB"
    comment = ""
    wanted_name = "Operation Log"
    wanted_hotkey = ""

    def init(self):
        return OplogPluginMod()


def PLUGIN_ENTRY():
    return OplogPlugin()
