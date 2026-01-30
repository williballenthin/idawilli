import logging
from typing import TYPE_CHECKING
from datetime import datetime
from dataclasses import dataclass

from PyQt5 import QtCore

import ida_name
import ida_bytes
import ida_funcs
import ida_lines
import ida_idaapi
import ida_kernwin

from oplog_events import Events, current_item_changed_event
from oplog_render import render_event

if TYPE_CHECKING:
    from oplog import oplog_plugmod_t

logger = logging.getLogger("oplog")


def addr_from_tag(raw: bytes) -> int:
    assert raw[0] == 0x01  # ida_lines.COLOR_ON
    assert raw[1] == ida_lines.COLOR_ADDR
    addr_hex = raw[2 : 2 + ida_lines.COLOR_ADDR_SIZE].decode("ascii")

    try:
        return int(addr_hex, 16)
    except ValueError:
        raise


def get_tagged_line_section_byte_offsets(section: ida_kernwin.tagged_line_section_t) -> tuple[int, int]:
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
    address: int | None


def get_current_tag(line: str, x: int) -> TaggedLineSection:
    ret = TaggedLineSection(ida_lines.COLOR_DEFAULT, line, None)

    tls = ida_kernwin.tagged_line_sections_t()
    if not ida_kernwin.parse_tagged_line_sections(tls, line):
        return ret

    current_section = tls.nearest_at(x, 0)
    if not current_section:
        return ret

    ret.tag = current_section.tag
    boring_line = ida_lines.tag_remove(line)
    ret.string = boring_line[current_section.start : current_section.start + current_section.length]

    current_section_start, _ = get_tagged_line_section_byte_offsets(current_section)
    addr_section = tls.nearest_before(current_section, x, ida_lines.COLOR_ADDR)
    if addr_section:
        addr_section_start, _ = get_tagged_line_section_byte_offsets(addr_section)
        addr_tag_start = addr_section_start - (ida_lines.COLOR_ADDR_SIZE + 2)
        assert addr_tag_start >= 0

        if current_section_start == addr_tag_start:
            raw = line.encode("utf-8")
            addr = addr_from_tag(raw[addr_tag_start : addr_tag_start + ida_lines.COLOR_ADDR_SIZE + 2])
            ret.address = addr

    return ret


class oplog_viewer_t(ida_kernwin.simplecustviewer_t):
    TITLE = "oplog"

    def __init__(self, events: Events):
        super().__init__()

        self.events: Events = events

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

        return True


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


class UILocationHook(ida_kernwin.UI_Hooks):
    def __init__(self, events: Events, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.events = events
        self._prev_item_ea = None

    @staticmethod
    def _get_item_head(ea: int) -> int:
        head_ea = ida_bytes.get_item_head(ea)
        func = ida_funcs.get_func(head_ea)
        if func is not None:
            head_ea = func.start_ea
        return head_ea

    def screen_ea_changed(self, ea: int, prev_ea: int) -> None:
        current_head_ea = self._get_item_head(ea)

        if current_head_ea == self._prev_item_ea:
            return

        current_name = ida_name.get_name(current_head_ea)
        prev_name = ida_name.get_name(self._prev_item_ea or 0) if self._prev_item_ea is not None else ""

        self._prev_item_ea = current_head_ea

        logger.debug(
            "current_item_changed(current_item_name=%s, prev_item_name=%s)",
            current_name,
            prev_name,
        )
        ev = current_item_changed_event(
            event_name="current_item_changed",
            timestamp=datetime.now(),
            current_item_ea=current_head_ea,
            current_item_name=current_name,
            prev_item_ea=self._prev_item_ea,
            prev_item_name=prev_name,
        )
        self.events.add_event(ev)


class UIManager:
    def __init__(self, plugmod: "oplog_plugmod_t", events: Events):
        self.plugmod = plugmod
        self.events = events
        self.viewer: oplog_viewer_t | None = None
        self.location_hooks: UILocationHook | None = None
        self.installation_hooks: create_desktop_widget_hooks_t | None = None

    def create_viewer(self) -> oplog_viewer_t:
        self.viewer = oplog_viewer_t(self.events)
        assert self.viewer.Create()
        assert self.viewer.Show()
        return self.viewer

    def setup(self):
        self.location_hooks = UILocationHook(self.events)
        self.location_hooks.hook()

        self.installation_hooks = create_desktop_widget_hooks_t(self.plugmod)
        self.installation_hooks.hook()

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "oplog:create", oplog_viewer_t.TITLE, create_oplog_widget_action_handler_t(self.plugmod)
            )
        )
        ida_kernwin.attach_action_to_menu("View/Open subviews/Strings", "oplog:create", ida_kernwin.SETMENU_APP)

        handler = save_events_to_file_handler_t(self.events)
        desc = ida_kernwin.action_desc_t(save_events_to_file_handler_t.ACTION_NAME, "Save to file...", handler)
        if not ida_kernwin.register_action(desc):
            logger.warning('Failed to register action "%s"' % save_events_to_file_handler_t.ACTION_NAME)

    def teardown(self):
        if not ida_kernwin.unregister_action(save_events_to_file_handler_t.ACTION_NAME):
            logger.warning('Failed to unregister action "%s"' % save_events_to_file_handler_t.ACTION_NAME)

        ida_kernwin.unregister_action("oplog:create")
        ida_kernwin.detach_action_from_menu("View/Open subviews/Strings", "oplog:create")

        if self.installation_hooks:
            self.installation_hooks.unhook()

        if self.location_hooks:
            self.location_hooks.unhook()
