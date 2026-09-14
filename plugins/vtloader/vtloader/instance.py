"""Start another IDA instance that loads a file through the vtloader loader."""

import logging
import os
import subprocess
import tempfile
from pathlib import Path

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
