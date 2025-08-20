import logging
from datetime import datetime
from dataclasses import dataclass

from PyQt5 import QtCore

import ida_name
import ida_lines
import ida_funcs
import ida_idaapi
import ida_kernwin
from ida_lines import COLSTR

from oplog_hooks import IDBChangedHook
from oplog_events import renamed_event, frame_udm_renamed_event

logger = logging.getLogger(__name__)


def pretty_date(time: datetime):
    """
    Get a datetime object or a int() Epoch timestamp and return a
    pretty string like 'an hour ago', 'Yesterday', '3 months ago',
    'just now', etc

    via: https://stackoverflow.com/a/1551394
    """
    now = datetime.now()
    diff = now - time
    second_diff = diff.seconds
    day_diff = diff.days

    if day_diff < 0:
        return ''

    if day_diff == 0:
        if second_diff < 10:
            return "just now"
        if second_diff < 60:
            return str(second_diff) + " seconds ago"
        if second_diff < 120:
            return "a minute ago"
        if second_diff < 3600:
            return str(second_diff // 60) + " minutes ago"
        if second_diff < 7200:
            return "an hour ago"
        if second_diff < 86400:
            return str(second_diff // 3600) + " hours ago"
    if day_diff == 1:
        return "Yesterday"
    if day_diff < 7:
        return str(day_diff) + " days ago"
    if day_diff < 31:
        return str(day_diff // 7) + " weeks ago"
    if day_diff < 365:
        return str(day_diff // 30) + " months ago"
    return str(day_diff // 365) + " years ago"


def addr_from_tag(tag: str) -> int:
    assert tag.startswith(ida_lines.SCOLOR_ON + ida_lines.SCOLOR_ADDR)
    addr_hex = tag[2:2 + ida_lines.COLOR_ADDR_SIZE]

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

    # TODO: verify with multi-byte UTF-8, since these are byte offsets, but we're operating on Python strings
    text_start_s = s[text_start_index + len("text_start="):].partition(",")[0]
    text_end_s = s[text_end_index + len("text_end="):].partition("}")[0]

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
    ret.string = boring_line[current_section.start:current_section.start + current_section.length]

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
        # addr_section_start initially points just after the address data (ON ADDR 001122...FF)
        # so rewind to the start of the tag (16 bytes of hex integer, 2 bytes of tags "ON ADDR")
        addr_tag_start = addr_section_start - (ida_lines.COLOR_ADDR_SIZE + 2)
        assert addr_tag_start >= 0

        # and this should match current_section_start, since that points just after the tag "ON SYMBOL"
        # if it doesn't, we're dealing with an edge case we didn't prepare for
        # maybe like multiple ADDR tags or something.
        # skip those and stick to things we know.
        if current_section_start == addr_tag_start:
            addr = addr_from_tag(line[addr_tag_start:])
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

    def render_address(self, ea: int):
        return ida_lines.COLSTR(f"{ea:016x}", ida_lines.SCOLOR_ADDR)

    def render_renamed(self, ev: renamed_event):
        return f"{pretty_date(ev.timestamp)}: address renamed: {COLSTR(ev.old_name, ida_lines.SCOLOR_CNAME)} → {COLSTR(ev.new_name, ida_lines.SCOLOR_CNAME)} at {ida_lines.tag_addr(ev.ea)}foo {COLSTR(self.render_address(ev.ea) + hex(ev.ea), ida_lines.SCOLOR_PREFIX)}"

    def render_frame_udm_renamed(self, ev: frame_udm_renamed_event):
        func_name = ida_funcs.get_func_name(ev.func_ea)
        return f"{pretty_date(ev.timestamp)}: local variable renamed: {ev.oldname} → {ev.udm.name} in {func_name}@{self.render_address(ev.func_ea)}"

    def render(self):
        for event in reversed(self.idb_events.events):
            if event.event_name == "renamed":
                self.AddLine(self.render_renamed(event))
            elif event.event_name == "frame_udm_renamed":
                self.AddLine(self.render_frame_udm_renamed(event))
            else:
                self.AddLine(f"{event.timestamp.isoformat('T')}: {event.event_name}")
        #self.AddLine(COLSTR(ida_lines.tag_addr(0x10001000) + "...", ida_lines.SCOLOR_PREFIX))

    def OnDblClick(self, shift):
        line = self.GetCurrentLine()
        if not line:
            return False

        _linen, x, _y = self.GetPos()

        section = get_current_tag(line, x)
        if section.address is not None:
            print(f"jumping to address {section.address:x}")
            ida_kernwin.jumpto(section.address)

        item_address = ida_name.get_name_ea(0, section.string)
        if item_address != ida_idaapi.BADADDR:
            logger.debug(f"found address for '{section.string}': {item_address:x}")
            print(f"jumping to address {item_address:x}")
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


class oplog_plugmod_t(ida_idaapi.plugmod_t):
    ACTION_NAME = "oplog:create"
    MENU_PATH = "View/Open subviews/Strings"

    def __init__(self):
        self.idb_hooks: IDBChangedHook | None = None
        self.viewer: oplog_viewer_t | None = None
        self.installation_hooks: create_desktop_widget_hooks_t | None = None

        # IDA doesn't invoke this for plugmod_t, only plugin_t
        self.init()

    def create_viewer(self) -> oplog_viewer_t:
        self.viewer = oplog_viewer_t(self.idb_hooks)
        assert(self.viewer.Create())
        assert(self.viewer.Show())
        return self.viewer

    def register_open_action(self):
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                self.ACTION_NAME,
                oplog_viewer_t.TITLE,
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
        self.register_idb_hooks()

    def run(self, arg):
        # do things here that users invoke via the menu entry (edit > plugins > ...)
        pass

    def term(self):
        self.unregister_open_action()
        self.unregister_idb_hooks()
        self.unregister_autoinst_hooks()
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
