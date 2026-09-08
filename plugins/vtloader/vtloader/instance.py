"""Start another IDA instance that loads a file through one of the vtloader loaders."""

import logging
import os
import subprocess
import tempfile
from pathlib import Path

from vtloader.options import PLUGIN_OPTIONS_NAME
from vtloader.settings import VT_FORMAT_NAME

logger = logging.getLogger(__name__)


def create_vt_input_file(sha256: str) -> Path:
    """Create the minimal input file that makes IDA invoke the VirusTotal loader.

    Each launch gets a private directory under the system temporary directory so
    concurrent or repeated loads of the same hash cannot reuse an older file.
    IDA's initial input bookkeeping reads a 16-byte block even though the selected
    loader ignores the input, so the file contains 16 null bytes. Naming the file
    after the hash gives IDA a meaningful input name while the new database is
    being initialized.
    """
    directory = Path(tempfile.mkdtemp(prefix="vtloader-vt-"))
    input_file = directory / sha256
    input_file.write_bytes(b"\0" * 16)
    return input_file


def get_ida_executable(idadir: Path) -> Path:
    """The IDA GUI executable in ``idadir``.

    Raises:
        FileNotFoundError: the executable is not there.
    """
    path = idadir / ("ida.exe" if os.name == "nt" else "ida")
    if not path.is_file():
        raise FileNotFoundError(f"IDA executable not found at {path}")
    return path


def build_vt_load_command(
    ida: Path, sha256: str, database: Path, input_file: Path
) -> list[str]:
    """Command line for an IDA instance that fetches ``sha256`` from VirusTotal into ``database``.

    ``-T`` selects the loader so that no load dialog appears, ``-O`` passes the hash,
    and ``-o`` puts the database where the loader would place it anyway, so IDA's
    working files are created there from the start. ``input_file`` must exist; the
    loader ignores its content.
    """
    return [
        str(ida),
        f"-T{VT_FORMAT_NAME}",
        f"-O{PLUGIN_OPTIONS_NAME}:sha256={sha256}",
        f"-o{database}",
        str(input_file),
    ]


def build_open_command(ida: Path, database: Path) -> list[str]:
    return [str(ida), str(database)]


def launch(command: list[str]) -> None:
    """Start ``command`` detached from this process.

    Raises:
        OSError: the process cannot be started.
    """
    logger.info("starting %s", subprocess.list2cmdline(command))
    subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
