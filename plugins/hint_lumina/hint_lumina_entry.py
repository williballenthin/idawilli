"""
IDA plugin that shows the Lumina record and history of a function as a hint.

Hover over the function name in the function header, such as the prototype or the
"proc near" line, to query the Lumina servers for that function.
"""

import logging

import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_lines
from hint_lumina import (
    LuminaRecord,
    get_function_names,
    get_function_records,
    is_name_at,
    render_hint,
)

logger = logging.getLogger(__name__)


class LuminaHintsHook(ida_kernwin.UI_Hooks):
    def __init__(self) -> None:
        super().__init__()
        self.cache: dict[int, list[LuminaRecord] | str] = {}

    def get_records(self, func_ea: int) -> list[LuminaRecord] | str:
        if func_ea not in self.cache:
            try:
                logger.info("querying Lumina for the function at %#x", func_ea)
                self.cache[func_ea] = get_function_records(func_ea)
            except RuntimeError as e:
                self.cache[func_ea] = f"Lumina: error: {e}"
        return self.cache[func_ea]

    def get_custom_viewer_hint(self, view, place: ida_kernwin.place_t | None):
        if not place:
            return None

        try:
            if ida_kernwin.get_widget_type(view) != ida_kernwin.BWN_DISASM:
                return None

            ea = place.toea()
            if ida_funcs.get_func_start(ea) != ea:
                return None

            viewer_place = ida_kernwin.get_custom_viewer_place(view, True)
            if len(viewer_place) != 3:
                return None
            _, x, _y = viewer_place

            line = ida_lines.tag_remove(
                ida_kernwin.get_custom_viewer_curline(view, True)
            )
            names = get_function_names(ea)
            if not is_name_at(line, x, names):
                return None

            records = self.get_records(ea)
            text = (
                records if isinstance(records, str) else render_hint(records, names[0])
            )
            return text, len(text.splitlines())
        except Exception as e:
            logger.warning("unexpected exception: %s", e, exc_info=True)
            return None


class LuminaHintsPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP | ida_idaapi.PLUGIN_HIDE
    comment = "Show the Lumina record and history of a function as a hint."
    help = "Hover over the function name in the function header."
    wanted_name = "Hint Lumina"
    wanted_hotkey = ""

    def __init__(self):
        super().__init__()
        self.hooks: LuminaHintsHook | None = None

    def init(self):
        self.hooks = LuminaHintsHook()
        if self.hooks.hook():
            return ida_idaapi.PLUGIN_KEEP
        logger.warning("failed to install the UI hooks")
        return ida_idaapi.PLUGIN_SKIP

    def term(self):
        if self.hooks:
            self.hooks.unhook()
            self.hooks = None


def PLUGIN_ENTRY():
    return LuminaHintsPlugin()
