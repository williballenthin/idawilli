"""Memloader plugin entry point.

At IDA startup the plugin keeps the Memloader loader links in ``$IDAUSR/loaders/`` up
to date, so that the ZIP, URL and VirusTotal loaders appear in the "Load a new file"
dialog. Its menu entry fetches a file from VirusTotal by SHA-256 into a new IDA
instance, with the database written to the Downloads directory.
"""

import logging
from pathlib import Path

import ida_diskio
import ida_idaapi
import ida_kernwin
import idc
from memloader.core import UserCancelled, get_database_extension, wait_box
from memloader.install import install_loader_links
from memloader.instance import (
    build_open_command,
    build_vt_load_command,
    create_vt_input_file,
    get_ida_executable,
    launch,
)
from memloader.settings import (
    PLUGIN_NAME,
    VT_HASH_PROMPT,
    ApiKeyMissingError,
    SettingsError,
    get_vt_api_key,
    get_vt_database_dir,
)
from memloader.virustotal import (
    InvalidHashError,
    VirusTotalClient,
    VirusTotalError,
    normalize_sha256,
)

PLUGIN_ROOT = Path(__file__).resolve().parent
SETTINGS_HINT = (
    "Set the VirusTotal API key in the Memloader plugin settings.\n"
    "Without the settings editor plugin, run: hcli plugin config set memloader vt_api_key <key>"
)

logger = logging.getLogger("memloader")


def show_plugin_settings() -> bool:
    """Open the settings editor on this plugin. False when the editor plugin is not installed."""
    result = idc.eval_idc(f'ida_settings_show_plugin_settings("{PLUGIN_NAME}")')
    if isinstance(result, str) and result.startswith("IDC_FAILURE"):
        logger.debug("settings editor unavailable: %s", result)
        return False
    return True


def ask_sha256() -> str:
    """Raises UserCancelled when the prompt is dismissed and InvalidHashError for bad input."""
    text = ida_kernwin.ask_str("", ida_kernwin.HIST_SRCH, VT_HASH_PROMPT)
    if not text:
        raise UserCancelled("no hash entered")
    return normalize_sha256(text)


def choose_existing_database(database: Path) -> bool:
    """Ask what to do with an existing database. True to open it, False to replace it.

    Raises:
        UserCancelled: the user chose neither.
    """
    answer = ida_kernwin.ask_buttons(
        "Open",
        "Replace",
        "Cancel",
        ida_kernwin.ASKBTN_YES,
        f"{database} already exists.\nOpen it, or replace it?",
    )
    if answer == ida_kernwin.ASKBTN_YES:
        return True
    if answer == ida_kernwin.ASKBTN_NO:
        return False
    raise UserCancelled("user cancelled")


def load_from_virustotal() -> None:
    """Prompt for a hash, check it against VirusTotal, and open it in a new IDA instance.

    Raises:
        UserCancelled: a prompt was dismissed.
        InvalidHashError: the entered text is not a SHA-256 digest.
        VirusTotalError: VirusTotal refused the key or does not know the file.
        SettingsError: the plugin settings cannot be read.
        FileNotFoundError: the IDA executable is missing.
        OSError: the new instance cannot be started.
    """
    try:
        api_key = get_vt_api_key()
    except ApiKeyMissingError:
        if not show_plugin_settings():
            ida_kernwin.warning(SETTINGS_HINT)
        else:
            ida_kernwin.info(
                "Memloader needs a VirusTotal API key.\nEnter it in the settings, then run the plugin again."
            )
        return

    sha256 = ask_sha256()
    ida = get_ida_executable(Path(ida_diskio.idadir("")))
    database = get_vt_database_dir() / (sha256 + get_database_extension())
    if database.exists() and choose_existing_database(database):
        launch(build_open_command(ida, database))
        return

    with wait_box(f"Checking {sha256[:16]}... on VirusTotal"):
        VirusTotalClient(api_key).get_download_url(sha256)
    database.parent.mkdir(parents=True, exist_ok=True)
    input_file = create_vt_input_file(sha256)
    launch(build_vt_load_command(ida, sha256, database, input_file))
    ida_kernwin.msg(f"Memloader: loading {sha256} from VirusTotal into {database}\n")


class MemloaderPlugmod(ida_idaapi.plugmod_t):
    def __init__(self):
        super().__init__()
        loaders_dir = Path(ida_diskio.get_user_idadir()) / "loaders"
        try:
            paths = install_loader_links(loaders_dir, PLUGIN_ROOT)
        except OSError as e:
            logger.warning(
                "Memloader: cannot install loader links into %s: %s", loaders_dir, e
            )
        else:
            logger.debug(
                "Memloader: loader links current in %s: %s",
                loaders_dir,
                [p.name for p in paths],
            )

    def run(self, arg):
        try:
            load_from_virustotal()
        except UserCancelled as e:
            logger.debug("Memloader: %s", e)
        except (InvalidHashError, VirusTotalError, SettingsError, OSError) as e:
            ida_kernwin.warning(f"Memloader: {e}")
        return True


class MemloaderPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_MULTI
    wanted_name = "Memloader: load from VirusTotal"
    wanted_hotkey = ""
    comment = (
        "Fetch a file from VirusTotal by SHA-256 and load it without writing it to disk"
    )
    help = ""

    def init(self):
        return MemloaderPlugmod()


def PLUGIN_ENTRY():
    return MemloaderPlugin()
