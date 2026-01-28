# Headless Mode Refactoring Plan

## Goal

Split oplog plugin into GUI and headless components so it can run in idalib without PyQt5.

## Components Analysis

### Move to `oplog_ui.py` (GUI-only)

From `oplog.py`:
- `addr_from_tag()` - used by viewer double-click
- `get_tagged_line_section_byte_offsets()` - used by viewer double-click
- `TaggedLineSection` dataclass - used by viewer double-click
- `get_current_tag()` - used by viewer double-click
- `oplog_viewer_t` class - custom viewer widget
- `create_oplog_widget_action_handler_t` class - action to open viewer
- `create_desktop_widget_hooks_t` class - auto-restore viewer on desktop
- `save_events_to_file_handler_t` class - context menu action for saving

From `oplog_hooks.py`:
- `UILocationHook` class - tracks cursor/screen position changes

### Keep in `oplog.py` (core)

- `OUR_NETNODE` constant
- `save_events()` - persist to IDB
- `load_events()` - load from IDB
- `UI_Closing_Hooks` - save on close/quit/save actions
- `oplog_plugmod_t` - main plugin module (modified for conditional GUI)
- `oplog_plugin_t` - plugin entry point (modified for headless)

### New functionality

- `is_gui_available()` - detect GUI vs headless
- `oplog_export(path)` IDC function - export events to JSON file
- `del_idc_func()` call in term - unregister IDC function

## Execution Steps

### Step 1: Create `oplog_ui.py`

Create new file with:
- All imports needed for GUI (PyQt5, ida_kernwin viewer stuff)
- Tag parsing functions
- `oplog_viewer_t`
- `create_oplog_widget_action_handler_t`
- `create_desktop_widget_hooks_t`
- `save_events_to_file_handler_t`
- `UILocationHook` (moved from oplog_hooks.py)
- Export a `setup_ui(plugmod, events)` function
- Export a `teardown_ui(plugmod)` function

### Step 2: Modify `oplog_hooks.py`

- Remove `UILocationHook` class (moved to oplog_ui.py)

### Step 3: Modify `oplog.py`

1. Add `is_gui_available()` function:
   ```python
   def is_gui_available() -> bool:
       if os.environ.get("IDA_INTERACTIVE") == "0":
           return False
       return ida_kernwin.is_idaq()
   ```

2. Remove GUI components (moved to oplog_ui.py):
   - Remove `HAS_PYQT` check and PyQt5 import
   - Remove tag parsing functions
   - Remove `oplog_viewer_t`
   - Remove `create_oplog_widget_action_handler_t`
   - Remove `create_desktop_widget_hooks_t`
   - Remove `save_events_to_file_handler_t`

3. Add IDC function registration:
   ```python
   def register_export_idc_func(events: Events):
       def oplog_export_handler(path: str) -> int:
           Path(path).write_text(events.to_json())
           return 1
       ida_expr.add_idc_func("oplog_export", oplog_export_handler, (ida_expr.VT_STR,))

   def unregister_export_idc_func():
       ida_expr.del_idc_func("oplog_export")
   ```

4. Modify `oplog_plugmod_t`:
   - Remove viewer-related attributes and methods when headless
   - Conditionally import and call `oplog_ui.setup_ui()` / `teardown_ui()`
   - Always register IDC export function

5. Modify `oplog_plugin_t.init()`:
   - Remove `HAS_PYQT` check
   - Plugin should always load (headless or GUI)

### Step 4: Update imports in `oplog_render.py`

- Check if any GUI-specific imports need guarding (probably fine as-is since only imported by UI)

## File Changes Summary

| File | Action |
|------|--------|
| `oplog_ui.py` | **Create** - all GUI code |
| `oplog.py` | **Modify** - remove GUI, add headless support |
| `oplog_hooks.py` | **Modify** - remove UILocationHook |
| `oplog_render.py` | No changes (only imported by UI) |
| `oplog_events.py` | No changes |
| `oplog_entry.py` | No changes |

## Testing

After refactoring:
1. Test GUI mode: Open IDA normally, verify viewer works
2. Test headless mode: Use idalib, verify no import errors, verify `oplog_export()` works
