import logging
from dataclasses import dataclass

import ida_name
import ida_lines
import ida_idaapi
import ida_kernwin
from PyQt5 import QtCore

from oplog_hooks import IDBChangedHook
from oplog_render import render_event

logger = logging.getLogger(__name__)


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

    def __init__(self, idb_events: IDBChangedHook):
        super().__init__()

        self.idb_events: IDBChangedHook = idb_events
        # we'll use a timer to check for new events periodically
        # rather than re-rendering on every event, which might be expensive
        self.timer: QtCore.QTimer = QtCore.QTimer()
        self.timer.timeout.connect(self.on_timer_timeout)

    def Create(self):
        if not ida_kernwin.simplecustviewer_t.Create(self, self.TITLE):
            return False

        self.render()
        self.timer.start(250)

        return True

    def on_timer_timeout(self):
        if self.idb_events.has_new.is_set():
            self.idb_events.has_new.clear()
            self.render()

    def OnClose(self):
        self.timer.stop()

    def render(self):
        self.ClearLines()
        last_line_prefix = ""
        for event in reversed(self.idb_events.events):
            # group the events with the same fuzzy timestamp ("2 minutes ago")
            line = render_event(event)
            if last_line_prefix:
                if line.startswith(last_line_prefix):
                    line = (" " * len(last_line_prefix)) + line[len(last_line_prefix):]
                else:
                    last_line_prefix = line.partition(":")[0] + ":"
            else:
                last_line_prefix = line.partition(":")[0] + ":"

            self.AddLine(line)

        # self.AddLine(COLSTR(ida_lines.tag_addr(0x10001000) + "...", ida_lines.SCOLOR_PREFIX))

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


import zlib
from pydantic import RootModel
from oplog_events import idb_event


EventList = RootModel[list[idb_event]]


def serialize_events(events: list[idb_event]) -> bytes:
    l = EventList(events)
    doc = l.model_dump_json()
    buf = doc.encode("utf-8")
    return zlib.compress(buf)


def deserialize_events(buf: bytes) ->list[idb_event]:
    return EventList.model_validate_json(zlib.decompress(buf)).root


import ida_idp
import ida_netnode

OUR_NETNODE = "$ com.williballenthin.idawilli.oplog"


def save_events(events: list[idb_event]):
    buf = serialize_events(events)
    node = ida_netnode.netnode(OUR_NETNODE)
    node.setblob(buf, 0, "I")

    logger.info("saved %d events", len(events))


def load_events():
    node = ida_netnode.netnode(OUR_NETNODE)
    if not node:
        logger.info("no existing events (no node)")
        return Events([])

    buf = node.getblob(0, "I")
    if not buf:
        logger.info("no existing events (no data)")
        return Events([])

    events = deserialize_events(buf)
    logger.info("loaded %d events", len(events))
    return events


class IDB_Closing_Hooks(ida_idp.IDB_Hooks):
    def __init__(self, idb_hooks: IDBChangedHook, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.idb_hooks = idb_hooks

    def closebase(self) -> None:
        """The database will be closed now."""
        logger.info("closebase")
        save_events(self.idb_hooks.events)

    def savebase(self) -> None:
        """The database is being saved."""
        logger.info("savebase")
        save_events(self.idb_hooks.events)


class oplog_plugmod_t(ida_idaapi.plugmod_t):
    ACTION_NAME = "oplog:create"
    MENU_PATH = "View/Open subviews/Strings"

    def __init__(self):
        self.idb_hooks: IDBChangedHook | None = None
        self.closing_hooks: IDB_Closing_Hooks | None = None
        self.viewer: oplog_viewer_t | None = None
        self.installation_hooks: create_desktop_widget_hooks_t | None = None

        # IDA doesn't invoke this for plugmod_t, only plugin_t
        self.init()

    def create_viewer(self) -> oplog_viewer_t:
        assert self.idb_hooks is not None
        self.viewer = oplog_viewer_t(self.idb_hooks)
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
        events = load_events()
        self.idb_hooks = IDBChangedHook(events)
        self.idb_hooks.hook()

    def unregister_idb_hooks(self):
        if self.idb_hooks:
            self.idb_hooks.unhook()

    def register_closing_hooks(self):
        assert self.idb_hooks is not None
        self.closing_hooks = IDB_Closing_Hooks(self.idb_hooks)
        self.closing_hooks.hook()

    def unregister_closing_hooks(self):
        if self.closing_hooks:
            self.closing_hooks.unhook()

    def init(self):
        # do things here that will always run,
        #  and don't require the menu entry (edit > plugins > ...) being selected.
        #
        # note: IDA doesn't call init, we do in __init__
        self.register_idb_hooks()
        self.register_autoinst_hooks()
        self.register_open_action()
        self.register_closing_hooks()
        # TODO: log also to a netnode
        # TODO: restore from a netnode
        # TODO: confirm what happens when a new file is opened/closed. reset the events.

    def run(self, arg):
        # do things here that users invoke via the menu entry (edit > plugins > ...)
        assert self.idb_hooks is not None
        save_events(self.idb_hooks.events)

    def term(self):
        self.unregister_closing_hooks()
        self.unregister_open_action()
        self.unregister_autoinst_hooks()
        self.unregister_idb_hooks()
        self.events.clear()


class oplog_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    help = "Log activity in the current IDB"
    comment = ""
    # TODO: don't show in plugins menu
    wanted_name = "Operation Log"
    wanted_hotkey = ""

    def init(self):
        return oplog_plugmod_t()


def PLUGIN_ENTRY():
    return oplog_plugin_t()
