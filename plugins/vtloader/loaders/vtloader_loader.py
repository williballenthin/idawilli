"""IDA loader entry for vtloader. IDA reaches it through a symlink in ``$IDAUSR/loaders/``.

IDA puts every plugin directory on ``sys.path`` at startup, so the package imports
directly. The functions are defined here rather than imported because IDAPython runs a
loader function with this module's namespace as its globals.
"""

import types

import ida_diskio
import ida_kernwin

loader: types.ModuleType | None
try:
    from vtloader import loader as _module
except ModuleNotFoundError as e:
    if e.name != "vtloader":
        raise
    loader = None
    ida_kernwin.msg(
        "vtloader: the plugin is not installed, but its loader entry remains. "
        f"Delete {ida_diskio.get_user_idadir()}/loaders/vtloader_loader.py to remove this message.\n"
    )
else:
    loader = _module


def accept_file(li, filename):
    if loader is None:
        return 0
    return loader.accept_file(li, filename)


def load_file(li, neflags, format):
    if loader is None:
        raise RuntimeError("vtloader plugin is not installed")
    return loader.load_file(li, neflags, format)
