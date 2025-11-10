# TODO: what happens during redo

import zlib
import logging
from dataclasses import dataclass

import ida_name
import ida_auto
import ida_lines
import ida_idaapi
import ida_kernwin
import ida_netnode
HAS_PYQT = False
try:
    from PyQt5 import QtCore
    HAS_PYQT = True
except ImportError:
    pass

from oplog_hooks import IDBChangedHook, UILocationHook
from oplog_events import Events
from oplog_render import render_event

logger = logging.getLogger("oplog")


def addr_from_tag(raw: bytes) -> int:
    assert raw[0] == 0x01  # ida_lines.COLOR_ON
    assert raw[1] == ida_lines.COLOR_ADDR
    addr_hex = raw[2 : 2 + ida_lines.COLOR_ADDR_SIZE].decode("ascii")

    try:
        # Parse as hex address (IDA uses qsscanf with "%a" format)
        return int(addr_hex, 16)
    except ValueError:
        raise


def get_tagged_line_section_byte_offsets(section: ida_kernwin.tagged_line_section_t) -> tuple[int, int]:
    # tagged_line_section_t.byte_offsets is not exposed by swig
    # so we parse directly from the string representation (puke)
    s = str(section)
    text_start_index = s.index("text_start=")
    text_end_index = s.index("text_end=")

    text_start_s = s[text_start_index + len("text_start=") :].partition(",")[0]
    text_end_s = s[text_end_index + len("text_end=") :].partition("}")[0]

    return int(text_start_s), int(text_end_s)


@dataclass
class TaggedLineSection:
    tag: int
    string: str
    # valid when the found tag section starts with an embedded address
    address: int | None


def get_current_tag(line: str, x: int) -> TaggedLineSection:
    ret = TaggedLineSection(ida_lines.COLOR_DEFAULT, line, None)

    tls = ida_kernwin.tagged_line_sections_t()
    if not ida_kernwin.parse_tagged_line_sections(tls, line):
        return ret

    # find any section at the X coordinate
    current_section = tls.nearest_at(x, 0)  # 0 = any tag
    if not current_section:
        # TODO: we only want the section that isn't tagged
        # while there might be a section totally before or totally after x.
        return ret

    ret.tag = current_section.tag
    boring_line = ida_lines.tag_remove(line)
    ret.string = boring_line[current_section.start : current_section.start + current_section.length]

    # try to find an embedded address at the start of the current segment
    current_section_start, _ = get_tagged_line_section_byte_offsets(current_section)
    addr_section = tls.nearest_before(current_section, x, ida_lines.COLOR_ADDR)
    if addr_section:
        # expect this layout
        #         ON SYMBOL ON ADDR 0011223344...EEFF "foo"      OFF SYMBOL
        # index   00 01     02 03   04 ...         19  20...N-1  N   N+1
        #                   ^ current_section_start         ^ current_section_end
        #                                              ^ addr_section_start and end (zero length)
        #                   ^ addr_tag_start
        #
        # COLOR_ADDR sections are zero-length and contain embedded addresses

        addr_section_start, _ = get_tagged_line_section_byte_offsets(addr_section)

        # print(boring_line)
        # print(line.encode("utf-8").hex())
        # print(("  " * current_section_start) + "^")
        # print(("  " * addr_section_start) + "*")
        # print(current_section_start)
        # print(addr_section_start)

        # addr_section_start initially points just after the address data (ON ADDR 001122...FF)
        # so rewind to the start of the tag (16 bytes of hex integer, 2 bytes of tags "ON ADDR")
        addr_tag_start = addr_section_start - (ida_lines.COLOR_ADDR_SIZE + 2)
        # print(("  " * addr_tag_start) + "%")
        assert addr_tag_start >= 0

        # and this should match current_section_start, since that points just after the tag "ON SYMBOL"
        # if it doesn't, we're dealing with an edge case we didn't prepare for
        # maybe like multiple ADDR tags or something.
        # skip those and stick to things we know.
        if current_section_start == addr_tag_start:
            # I'm not sure if the following is correct or not, proceed with caution:
            #
            # IDA places raw bytes into the line buffer to represent the tags.
            # But they're not meant to be interpreted as characters, but raw byte values.
            # So we can run into trouble when something like COLOR_CREF + "foo" collides with a UTF-8 (or Python internal) string representation,
            #  because Python might return some weird Unicode character when accessing that index.
            # So we try to convert the string buffer to raw bytes and operate on that.
            #
            # However, I think this is pretty unsafe, since the internal string representation in Python is not constant:
            # https://stackoverflow.com/a/9079985
            #
            # The correct fix is probably considering anything with tags in it to be raw bytes,
            # though this is probably inconvenient.
            raw = line.encode("utf-8")
            addr = addr_from_tag(raw[addr_tag_start : addr_tag_start + ida_lines.COLOR_ADDR_SIZE + 2])
            ret.address = addr

    return ret


class oplog_viewer_t(ida_kernwin.simplecustviewer_t):
    TITLE = "oplog"

    def __init__(self, events: Events):
        super().__init__()

        self.events: Events = events

        # we'll use a timer to check for new events periodically
        # rather than re-rendering on every event, which might be expensive
        self.timer: QtCore.QTimer = QtCore.QTimer()
        self.timer.timeout.connect(self.on_timer_timeout)

    def Create(self):
        if not super().Create(self.TITLE):
            return False

        self.render()
        self.timer.start(250)

        return True

    def Show(self, *args):
        if not super().Show(*args):
            return False

        ida_kernwin.attach_action_to_popup(self.GetWidget(), None, save_events_to_file_handler_t.ACTION_NAME)
        return True

    def on_timer_timeout(self):
        if self.events.has_new.is_set():
            self.events.has_new.clear()
            self.render()

    def OnClose(self):
        self.timer.stop()

    def render(self):
        self.ClearLines()
        last_line_prefix = ""
        for event in reversed(self.events.events):
            # group the events with the same fuzzy timestamp ("2 minutes ago")
            line = render_event(event)
            if last_line_prefix:
                if line.startswith(last_line_prefix):
                    line = (" " * len(last_line_prefix)) + line[len(last_line_prefix) :]
                else:
                    last_line_prefix = line.partition(":")[0] + ":"
            else:
                last_line_prefix = line.partition(":")[0] + ":"

            self.AddLine(line)

    def OnDblClick(self, shift):
        line = self.GetCurrentLine()
        if not line:
            return False

        _linen, x, _y = self.GetPos()

        section = get_current_tag(line, x)
        if section.address is not None:
            ida_kernwin.jumpto(section.address)

        item_address = ida_name.get_name_ea(0, section.string)
        if item_address != ida_idaapi.BADADDR:
            logger.debug(f"found address for '{section.string}': {item_address:x}")
            ida_kernwin.jumpto(item_address)

        return True  # handled


class create_oplog_widget_action_handler_t(ida_kernwin.action_handler_t):
    def __init__(self, plugmod: "oplog_plugmod_t", *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.plugmod = plugmod

    def activate(self, ctx):
        if ida_kernwin.find_widget(oplog_viewer_t.TITLE) is None:
            self.plugmod.create_viewer()

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class create_desktop_widget_hooks_t(ida_kernwin.UI_Hooks):
    def __init__(self, plugmod: "oplog_plugmod_t", *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.plugmod = plugmod

    def create_desktop_widget(self, ttl, cfg):
        if ttl == oplog_viewer_t.TITLE:
            return self.plugmod.create_viewer().GetWidget()


OUR_NETNODE = "$ com.williballenthin.idawilli.oplog"


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


class save_events_to_file_handler_t(ida_kernwin.action_handler_t):
    ACTION_NAME = "oplog:save"

    def __init__(self, events: Events, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.events = events

    def activate(self, ctx):
        filename = ida_kernwin.ask_file(1, "*.json", "Select the file to store events in a JSON format")
        if filename is None:
            return

        with open(filename, "wb") as f:
            f.write(self.events.to_json().encode("utf-8"))
        logger.info("saved %d events to %s", len(self.events.events), filename)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class UI_Closing_Hooks(ida_kernwin.UI_Hooks):
    """Respond to UI events and save the events into the database."""

    # we could also use IDB_Hooks, but I found it less reliable:
    # - closebase: "the database will be closed now", however, I couldn't figure out when its actually triggered.
    # - savebase: notified during File -> Save, but not File -> Close.
    # easier to keep all the hooks in one place.

    def __init__(self, events: Events, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.events = events

    def preprocess_action(self, action: str):
        if action == "CloseBase":
            # File -> Close
            logger.debug("action: CloseBase")
            save_events(self.events)
            return 0
        elif action == "QuitIDA":
            # File -> Quit
            logger.debug("action: QuitIDA")
            save_events(self.events)
            return 0
        elif action == "SaveBase":
            # File -> Save
            logger.debug("action: SaveBase")
            save_events(self.events)
            return 0
        else:
            return 0


class oplog_plugmod_t(ida_idaapi.plugmod_t):
    ACTION_NAME = "oplog:create"
    MENU_PATH = "View/Open subviews/Strings"

    def __init__(self):
        self.events: Events | None = None
        self.idb_hooks: IDBChangedHook | None = None
        self.location_hooks: UILocationHook | None = None
        self.ui_closing_hooks: UI_Closing_Hooks | None = None
        self.viewer: oplog_viewer_t | None = None
        self.installation_hooks: create_desktop_widget_hooks_t | None = None

        # IDA doesn't invoke this for plugmod_t, only plugin_t
        self.init()

    def create_viewer(self) -> oplog_viewer_t:
        assert self.events is not None
        self.viewer = oplog_viewer_t(self.events)
        assert self.viewer.Create()
        assert self.viewer.Show()
        return self.viewer

    def register_open_action(self):
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                self.ACTION_NAME, oplog_viewer_t.TITLE, create_oplog_widget_action_handler_t(self)
            )
        )

        # TODO: add icon
        ida_kernwin.attach_action_to_menu(self.MENU_PATH, self.ACTION_NAME, ida_kernwin.SETMENU_APP)

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
        assert self.events is not None
        self.idb_hooks = IDBChangedHook(self.events)
        self.idb_hooks.hook()

    def unregister_idb_hooks(self):
        if self.idb_hooks:
            self.idb_hooks.unhook()

    def register_location_hooks(self):
        assert self.events is not None
        self.location_hooks = UILocationHook(self.events)
        self.location_hooks.hook()

    def unregister_location_hooks(self):
        if self.location_hooks:
            self.location_hooks.unhook()

    def register_ui_closing_hooks(self):
        assert self.events is not None
        self.ui_closing_hooks = UI_Closing_Hooks(self.events)
        self.ui_closing_hooks.hook()

    def unregister_ui_closing_hooks(self):
        if self.ui_closing_hooks:
            self.ui_closing_hooks.unhook()

    def register_save_file_handler(self):
        assert self.events is not None
        handler = save_events_to_file_handler_t(self.events)
        desc = ida_kernwin.action_desc_t(save_events_to_file_handler_t.ACTION_NAME, "Save to file...", handler)
        if not ida_kernwin.register_action(desc):
            logger.warning('Failed to register action "%s"' % save_events_to_file_handler_t.ACTION_NAME)

    def unregister_save_file_handler(self):
        if not ida_kernwin.unregister_action(save_events_to_file_handler_t.ACTION_NAME):
            logger.warning('Failed to unregister action "%s"' % save_events_to_file_handler_t.ACTION_NAME)

    def init(self):
        # do things here that will always run,
        #  and don't require the menu entry (edit > plugins > ...) being selected.
        #
        # note: IDA doesn't call init, we do in __init__

        if not ida_auto.auto_is_ok():
            # don't capture events before auto-analysis is done, or we get all the system events.
            #
            # note:
            # - when we first load a program, this plugin will be run before auto-analysis is complete
            #   (actually, before auto-analysis even starts).
            #   so auto_is_ok() returns False
            # - when we load an existing IDB, auto_is_ok() return True.
            # so we can safely use this to wait until auto-analysis is complete for the first time.
            logger.debug("waiting for auto-analysis to complete before subscribing to events")
            ida_auto.auto_wait()
            logger.debug("auto-analysis complete, now subscribing to events")

        self.events = load_events()
        self.register_idb_hooks()
        self.register_location_hooks()
        self.register_autoinst_hooks()
        self.register_open_action()
        self.register_ui_closing_hooks()
        self.register_save_file_handler()

    def run(self, arg):
        # do things here that users invoke via the menu entry (edit > plugins > ...)
        assert self.idb_hooks is not None
        save_events(self.idb_hooks.events)

    def term(self):
        self.unregister_save_file_handler()
        self.unregister_ui_closing_hooks()
        self.unregister_open_action()
        self.unregister_autoinst_hooks()
        self.unregister_location_hooks()
        self.unregister_idb_hooks()
        assert self.events is not None
        self.events.clear()


class oplog_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    help = "Log activity in the current IDB"
    comment = ""
    # TODO: don't show in plugins menu
    wanted_name = "Operation Log"
    wanted_hotkey = ""

    def init(self):
        if HAS_PYQT:
            return oplog_plugmod_t()
        else:
            logger.warning("PyQt5 not found, skipping.")

