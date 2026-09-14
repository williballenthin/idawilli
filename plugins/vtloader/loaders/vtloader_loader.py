"""IDA loader entry for vtloader. IDA reaches it through a symlink in ``$IDAUSR/loaders/``.

IDA puts every plugin directory on ``sys.path`` at startup, so the package imports
directly. The functions are defined here rather than imported because IDAPython runs a
loader function with this module's namespace as its globals.
"""

from vtloader import loader


def accept_file(li, filename):
    return loader.accept_file(li, filename)


def load_file(li, neflags, format):
    return loader.load_file(li, neflags, format)
