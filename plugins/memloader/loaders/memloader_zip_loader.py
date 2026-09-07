"""IDA loader entry for Memloader ZIP. IDA reaches it through a link in ``$IDAUSR/loaders/``.

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

zip_loader: types.ModuleType | None
try:
    from memloader.loaders import zip_loader as _module
except ModuleNotFoundError as e:
    if e.name != "memloader":
        raise
    zip_loader = None
    ida_kernwin.msg(
        "Memloader: the plugin is not installed, but its loader entry remains. "
        f"Delete {ida_diskio.get_user_idadir()}/loaders/memloader_zip_loader.py to remove this message.\n"
    )
else:
    zip_loader = _module


def accept_file(li, filename):
    if zip_loader is None:
        return 0
    return zip_loader.accept_file(li, filename)


def load_file(li, neflags, format):
    if zip_loader is None:
        raise RuntimeError("Memloader plugin is not installed")
    return zip_loader.load_file(li, neflags, format)
