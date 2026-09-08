"""IDA loader entry for vtloader. IDA reaches it through a link in ``$IDAUSR/loaders/``.

IDA puts every plugin directory on ``sys.path`` at startup, so the package imports
directly. The functions are defined here rather than imported because IDAPython runs a
loader function with this module's namespace as its globals.

The link is symbolic on every platform. Only on Windows, when symbolic links are not
permitted, is a hard link made instead. Such a hard link keeps this file alive after
the plugin is uninstalled; the import then fails, the loader stays inert, and the
user is asked to delete the file.
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
