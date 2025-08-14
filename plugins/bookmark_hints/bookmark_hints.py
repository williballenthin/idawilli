"""
summary: show a hoverable icon on lines with a bookmark.

description:
  This plugin displays a hoverable icon on disassembly lines
  for which there is a bookmark. The hover hint shows the
  description of the mark, like "mark: what is this?". As
  bookmarks are added and removed, the icons are updated.
  
  We use the following concepts:
    * ida_moves.bookmarks_t: to fetch the marked locations for `IDA View-A`.
    * ida_idp.IDB_Hooks.bookmark_changed: to notify on bookmark add/remove/change.
    * ida_lines.user_defined_prefix_t: to add a line prefix containing an icon character.
    * ida_kernwin.UI_Hooks.get_custom_viewer_hint: to recognize the icon and show a popup hint.
  
  Ultimately, the functionality is a bit contrived, because the
  disassembly listing already highlights marked locations
  (see: https://hex-rays.com/blog/igors-tip-of-the-week-80-bookmarks).
  Still, this plugin shows how to dynamically provide prefixes and hints,
  while responding to database changes.

keywords: bookmarks, hooks, line prefix, hints

level: intermediate
"""

import ida_idp
import ida_lines
import ida_moves
import ida_idaapi
import ida_kernwin


def refresh_disassembly():
    ida_kernwin.request_refresh(ida_kernwin.IWID_DISASM)


def collect_bookmarks() -> dict[int, str]:
    ret: dict[int, str] = {}

    w = ida_kernwin.find_widget("IDA View-A")
    if not w:
        return ret

    for loc, desc in ida_moves.bookmarks_t(w):
        place = loc.place()
        if not place:
            continue

        addr = place.toea()
        if addr is None:
            continue

        assert isinstance(addr, int)
        assert isinstance(desc, str)

        ret[addr] = desc

    return ret


class BookmarksChangedHook(ida_idp.IDB_Hooks):
    def __init__(self, marks: dict[int, str], *args, **kwargs):
        """
        args:
            marks: shared dictionary that receives updated marks
        """
        super().__init__(*args, **kwargs)
        self.marks = marks

    def bookmark_changed(self, index, pos, desc, operation):
        self.marks.clear()
        self.marks.update(collect_bookmarks())

        # for add/remove, prefix may have changed,
        # so need to re-render disassembly.
        # if there's a way to re-render only some lines,
        # this could be optimized a bit.
        refresh_disassembly()


class BookmarksPrefix(ida_lines.user_defined_prefix_t):
    ICON = " β "
    # ICON = " B "

    def __init__(self, marks: dict[int, str]):
        """
        args:
            marks: shared dictionary that contain marks
        """
        super().__init__(len(self.ICON))
        self.marks = marks

    def get_user_defined_prefix(self, ea, insn, lnnum, indent, line):
        if ea in self.marks:
            # wrap the icon in color tags so its easy to identify.
            # otherwise, the icon may merge with other spans, which
            # makes checking for equality more difficult.
            return ida_lines.COLSTR(self.ICON, ida_lines.SCOLOR_SYMBOL)

        return " " * len(self.ICON)


class BookmarksHints(ida_kernwin.UI_Hooks):
    def __init__(self, prefixer: BookmarksPrefix, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prefixer = prefixer

    def get_custom_viewer_hint(self, viewer, place):
        if not place:
            return

        ea = place.toea()
        if not ea:
            return

        curline = ida_kernwin.get_custom_viewer_curline(viewer, True)
        curline = ida_lines.tag_remove(curline)
        _, x, _ = ida_kernwin.get_custom_viewer_place(viewer, True)

        if curline[x:].lstrip().startswith(self.prefixer.ICON.lstrip()):
            desc = self.prefixer.marks.get(ea)
            if not desc:
                return

            return (f"mark: {desc}", 1)


class BookmarkHintsPluginMod(ida_idaapi.plugmod_t):
    def __init__(self):
        # the `marks` dictionary instance will be shared by all the following objects
        # and mutated directly by `bookmark_hooks`.
        self.marks: dict[int, str] = {}
        self.bookmark_hooks: BookmarksChangedHook | None = None
        self.prefixer: BookmarksPrefix | None = None
        self.hinter: BookmarksHints | None = None

    def run(self, arg):
        self.marks.clear()
        self.marks.update(collect_bookmarks())

        self.bookmark_hooks = BookmarksChangedHook(self.marks)
        self.prefixer = BookmarksPrefix(self.marks)
        self.hinter = BookmarksHints(self.prefixer)

        self.bookmark_hooks.hook()
        # self.prefixer is installed simply by constructing it
        self.hinter.hook()

        # since we're updating the disassembly listing by adding the line prefix,
        # we need to re-render all the lines.
        refresh_disassembly()

    def term(self):
        if self.hinter is not None:
            self.hinter.unhook()

        if self.bookmark_hooks is not None:
            self.bookmark_hooks.unhook()

        self.marks = {}
        self.bookmark_hooks = None
        self.prefixer = None
        self.hinter = None

        # refresh and remove the prefix entries
        refresh_disassembly()


class BookmarkHintsPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    help = "Display hints for bookmarked locations"
    comment = "Uses icon: β"
    wanted_name = "Bookmark Hints"
    wanted_hotkey = ""

    def init(self):
        return BookmarkHintsPluginMod()


def PLUGIN_ENTRY():
    return BookmarkHintsPlugin()
