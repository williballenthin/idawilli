
# Bookmark Hints IDA Pro Plugin
Show a hoverable icon on lines with a bookmark.

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

![screen cast](https://github.com/williballenthin/idawilli/releases/download/v0.1.0a4/Screen.Recording.2025-08-14.at.11.33.52.AM.gif)
