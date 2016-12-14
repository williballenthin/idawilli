'''
example of:
  - providing custom UI hints with dynamic data from Python

in this silly example, we display UI hints with the current timestamp.
a more useful plugin might inspect the hovered line, and display some documentation.

Author: Willi Ballenthin <william.ballenthin@fireeye.com>
Licence: Apache 2.0
'''
import sys
import datetime

import idc
import idaapi
import idautils


class HintsHooks(idaapi.UI_Hooks):
    def get_custom_viewer_hint(self, view, place):
        curline = idaapi.get_custom_viewer_curline(view, True)
        _, x, y = idaapi.get_custom_viewer_place(view, True)
        ea = place.toea()

        return ('0x%08X: %s' % (place.toea(), datetime.datetime.now().isoformat(' ')), 1)

    def get_ea_hint(self, ea):
        return datetime.datetime.now().isoformat(' ')


class DynHints2Plugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Display dynamically-generated hints (2)."

    help = "Display dynamically-generated hints (2)."
    wanted_name = "DynHints2"
    wanted_hotkey = "Ctrl-["


    def init(self):
        self.hooks = HintsHooks()
        return idaapi.PLUGIN_OK

    def run(self, arg):
        print('hints2: run')
        self.hooks.hook()

    def term(self):
        print('hints2: term')
        self.hooks.unhook()


def PLUGIN_ENTRY():
    return DynHints2Plugin()
