"""flirt-data-pack plugin entry point.

At IDA startup the plugin links the shipped FLIRT signatures into
``$IDAUSR/sig/<proc>/`` so they appear in the "Apply FLIRT signature" dialog
and are found by ``plan_to_apply_idasgn()``. An IDB hook auto-applies the
appropriate signatures when a file finishes loading.
"""

import logging
from pathlib import Path

import ida_diskio
import ida_funcs
import ida_ida
import ida_idaapi
import ida_idp
from flirt_data_pack.apply import get_signatures_for
from flirt_data_pack.install import get_procs, install_sig_links

PLUGIN_ROOT = Path(__file__).resolve().parent

logger = logging.getLogger("flirt_data_pack")


class FlirtDataPackHooks(ida_idp.IDB_Hooks):
    def loader_finished(self, li, neflags, filetypename):
        filetype = ida_ida.inf_get_filetype()
        names = get_signatures_for(filetype)
        for name in names:
            logger.debug("flirt-data-pack: auto-applying signature %s", name)
            ida_funcs.plan_to_apply_idasgn(name)
        return 0


class FlirtDataPackPlugmod(ida_idaapi.plugmod_t):
    def __init__(self):
        super().__init__()
        user_dir = Path(ida_diskio.get_user_idadir())
        for proc in get_procs(PLUGIN_ROOT):
            sig_dir = user_dir / "sig" / proc
            try:
                paths = install_sig_links(sig_dir, PLUGIN_ROOT, proc)
            except OSError as e:
                logger.warning(
                    "flirt-data-pack: cannot install sig links into %s: %s",
                    sig_dir,
                    e,
                )
            else:
                for p in paths:
                    logger.debug("flirt-data-pack: sig link current at %s", p)

        self._hooks = FlirtDataPackHooks()
        self._hooks.hook()

    def __del__(self):
        try:
            self._hooks.unhook()
        except Exception:
            pass

    def run(self, arg):
        return False


class FlirtDataPackPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_MULTI
    wanted_name = "flirt-data-pack"
    wanted_hotkey = ""
    comment = "Install shipped FLIRT signatures into the user sig directory"
    help = ""

    def init(self):
        return FlirtDataPackPlugmod()


def PLUGIN_ENTRY():
    return FlirtDataPackPlugin()
