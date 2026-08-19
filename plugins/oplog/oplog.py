# TODO: what happens during redo

import logging
import os
import zlib
from pathlib import Path

import ida_auto
import ida_expr
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_netnode
from oplog_events import Events
from oplog_hooks import IDBChangedHook

logger = logging.getLogger("oplog")

OUR_NETNODE = "$ com.williballenthin.idawilli.oplog"


def is_gui_available() -> bool:
    if os.environ.get("IDA_INTERACTIVE") == "0":
        return False
    return ida_kernwin.is_idaq()


def save_events(events: Events):
    buf = zlib.compress(events.to_json().encode("utf-8"))

    node = ida_netnode.netnode(OUR_NETNODE)
    node.setblob(buf, 0, "I")

    logger.info("saved %d events", len(events))


def load_events() -> Events:
    node = ida_netnode.netnode(OUR_NETNODE)
    if not node:
        logger.info("no existing events (no node)")
        return Events([])

    buf = node.getblob(0, "I")
    if not buf:
        logger.info("no existing events (no data)")
        return Events([])

    events = Events.from_json(zlib.decompress(buf).decode("utf-8"))
    logger.info("loaded %d events", len(events))
    return events


class UI_Closing_Hooks(ida_kernwin.UI_Hooks):
    def __init__(self, events: Events, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.events = events

    def preprocess_action(self, action: str):
        if action == "CloseBase":
            logger.debug("action: CloseBase")
            save_events(self.events)
            return 0
        elif action == "QuitIDA":
            logger.debug("action: QuitIDA")
            save_events(self.events)
            return 0
        elif action == "SaveBase":
            logger.debug("action: SaveBase")
            save_events(self.events)
            return 0
        else:
            return 0


class AutoAnalysisHook(ida_idp.IDB_Hooks):
    def __init__(self, plugin: "oplog_plugmod_t", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.plugin = plugin

    def auto_empty_finally(self) -> None:
        self.plugin.on_autoanalysis_complete()


class oplog_plugmod_t(ida_idaapi.plugmod_t):
    def __init__(self):
        self.events: Events | None = None
        self.autoanalysis_hook: AutoAnalysisHook | None = None
        self.idb_hooks: IDBChangedHook | None = None
        self.ui_closing_hooks: UI_Closing_Hooks | None = None
        self.ui_manager = None
        self.has_gui = is_gui_available()

        self.init()

    def create_viewer(self):
        if self.ui_manager is not None:
            return self.ui_manager.create_viewer()
        return None

    def register_idb_hooks(self):
        assert self.events is not None
        self.idb_hooks = IDBChangedHook(self.events)
        self.idb_hooks.hook()

    def unregister_idb_hooks(self):
        if self.idb_hooks:
            self.idb_hooks.unhook()

    def register_ui_closing_hooks(self):
        assert self.events is not None
        self.ui_closing_hooks = UI_Closing_Hooks(self.events)
        self.ui_closing_hooks.hook()

    def unregister_ui_closing_hooks(self):
        if self.ui_closing_hooks:
            self.ui_closing_hooks.unhook()

    def register_export_idc_func(self):
        assert self.events is not None
        events = self.events

        def oplog_export_handler(path: str) -> int:
            try:
                Path(path).write_text(events.to_json())
                logger.info("exported %d events to %s", len(events), path)
                return 1
            except Exception as e:
                logger.error("failed to export events: %s", e)
                return 0

        if ida_expr.add_idc_func(
            "oplog_export", oplog_export_handler, (ida_expr.VT_STR,)
        ):
            logger.debug("registered oplog_export IDC function")
        else:
            logger.warning("failed to register oplog_export IDC function")

    def unregister_export_idc_func(self):
        ida_expr.del_idc_func("oplog_export")

    def init(self):
        if ida_auto.auto_is_ok():
            self.on_autoanalysis_complete()
            return

        logger.debug(
            "waiting for auto-analysis to complete before subscribing to events"
        )
        self.autoanalysis_hook = AutoAnalysisHook(self)
        self.autoanalysis_hook.hook()

        # Auto-analysis may have completed between the first check and hook().
        if ida_auto.auto_is_ok():
            self.on_autoanalysis_complete()

    def on_autoanalysis_complete(self):
        if self.events is not None:
            return

        if self.autoanalysis_hook is not None:
            self.autoanalysis_hook.unhook()
            self.autoanalysis_hook = None

        logger.debug("auto-analysis complete, now subscribing to events")
        self.events = load_events()
        self.register_idb_hooks()
        self.register_export_idc_func()

        if self.has_gui:
            self.register_ui_closing_hooks()

            from oplog_ui import UIManager

            self.ui_manager = UIManager(self, self.events)
            self.ui_manager.setup()

    def run(self, arg):
        if self.events is not None:
            save_events(self.events)

    def term(self):
        if self.autoanalysis_hook is not None:
            self.autoanalysis_hook.unhook()
            self.autoanalysis_hook = None

        if self.events is None:
            return

        if self.ui_manager is not None:
            self.ui_manager.teardown()

        self.unregister_ui_closing_hooks()
        self.unregister_export_idc_func()
        self.unregister_idb_hooks()
        self.events.clear()


class oplog_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    help = "Log activity in the current IDB"
    comment = ""
    wanted_name = "Operation Log"
    wanted_hotkey = ""

    def init(self):
        return oplog_plugmod_t()
