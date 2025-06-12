import sys
import logging

import idapro
import ida_auto
import ida_hexrays


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)
idapro.enable_console_messages(True)


input_path = sys.argv[1]

logger.info("opening database: %s", input_path)
if idapro.open_database(str(input_path), run_auto_analysis=True):
    raise RuntimeError("failed to analyze input file")

logger.debug("idalib: waiting for analysis...")
ida_auto.auto_wait()

if not ida_hexrays.init_hexrays_plugin():
    raise RuntimeError("failed to initialize Hex-Rays decompiler")

sys.exit(0)
