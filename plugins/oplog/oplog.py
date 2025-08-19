import logging

import ida_idaapi
import ida_kernwin

from oplog_hooks import IDBChangedHook

logger = logging.getLogger(__name__)

class OplogViewer(ida_kernwin.simplecustviewer_t):
    TITLE = "oplog"

    def __init__(self):
        ida_kernwin.simplecustviewer_t.__init__(self)

    def Create(self):
        if not ida_kernwin.simplecustviewer_t.Create(self, self.TITLE):
            return False

        text = "foo\nbar"
        for l in text.split("\n"):
            self.AddLine(l)
        return True


class create_oplog_widget_action_handler_t(ida_kernwin.action_handler_t):
    def __init__(self, plugmod: "OplogPluginMod", *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.plugmod = plugmod

    def activate(self, ctx):
        if ida_kernwin.find_widget(OplogViewer.TITLE) is None:
            self.plugmod.create_viewer()

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class create_desktop_widget_hooks_t(ida_kernwin.UI_Hooks):
    def __init__(self, plugmod: "OplogPluginMod", *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.plugmod = plugmod

    def create_desktop_widget(self, ttl, cfg):
        if ttl == OplogViewer.TITLE:
            return self.plugmod.create_viewer().GetWidget()


class OplogPluginMod(ida_idaapi.plugmod_t):
    ACTION_NAME = "oplog:create"
    MENU_PATH = "View/Open subviews/Strings"

    def __init__(self):
        self.idb_hooks: IDBChangedHook | None = None
        self.viewer: OplogViewer | None = None
        self.installation_hooks: create_desktop_widget_hooks_t | None = None

        # IDA doesn't invoke this for plugmod_t, only plugin_t
        self.init()

    def create_viewer(self) -> OplogViewer:
        self.viewer = OplogViewer()
        assert(self.viewer.Create())
        assert(self.viewer.Show())
        return self.viewer

    def register_open_action(self):
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                self.ACTION_NAME,
                OplogViewer.TITLE,
                create_oplog_widget_action_handler_t(self)))

        # TODO: add icon
        ida_kernwin.attach_action_to_menu(
            self.MENU_PATH,
            self.ACTION_NAME,
            ida_kernwin.SETMENU_APP)

    def unregister_open_action(self):
        ida_kernwin.unregister_action(self.ACTION_NAME)
        ida_kernwin.detach_action_from_menu(self.MENU_PATH, self.ACTION_NAME)

    def register_autoinst_hooks(self):
        self.installation_hooks = create_desktop_widget_hooks_t(self)
        assert self.installation_hooks is not None
        self.installation_hooks.hook()

    def unregister_autoinst_hooks(self):
        if self.installation_hooks:
            self.installation_hooks.unhook()

    def register_idb_hooks(self):
        self.idb_hooks = IDBChangedHook()
        self.idb_hooks.hook()

    def unregister_idb_hooks(self):
        if self.idb_hooks:
            self.idb_hooks.unhook()

    def init(self):
        # do things here that will always run,
        #  and don't require the menu entry (edit > plugins > ...) being selected.
        #
        # note: IDA doesn't call init, we do in __init__
        self.register_open_action()
        self.register_autoinst_hooks()
        self.register_autoinst_hooks()

    def run(self, arg):
        # do things here that users invoke via the menu entry (edit > plugins > ...)
        pass

    def term(self):
        self.unregister_open_action()
        self.unregister_idb_hooks()
        self.unregister_autoinst_hooks()


class OplogPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    help = "Log activity in the current IDB"
    comment = ""
    # TODO: don't show in plugins menu
    wanted_name = "Operation Log"
    wanted_hotkey = ""

    def init(self):
        return OplogPluginMod()


def PLUGIN_ENTRY():
    return OplogPlugin()
