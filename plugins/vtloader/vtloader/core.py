"""Pipeline that loads a downloaded buffer into the current IDA database."""

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import ida_entry
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_loader
import ida_nalt
import ida_segment

from vtloader.kernel import IdaKernel, LoaderInfo
from vtloader.options import PLUGIN_OPTIONS_NAME, LoadOptions

logger = logging.getLogger(__name__)

SHELLCODE_SEGMENT = "shellcode"
SHELLCODE_PROCESSOR = "metapc"


class LoadError(Exception):
    pass


class UserCancelled(LoadError):
    pass


@dataclass(frozen=True)
class LoadResult:
    filename: str
    loader: LoaderInfo | None
    filetype: int

    @property
    def is_shellcode(self) -> bool:
        return self.loader is None


def is_batch_mode() -> bool:
    return bool(ida_kernwin.cvar.batch)


_loading_buffer = False


def is_loading_buffer() -> bool:
    """True while a downloaded buffer is being offered to IDA's loaders.

    vtloader's loader accepts any input once it has a hash to fetch, so it is a
    candidate for the buffer it just downloaded. For a recognized format IDA's own
    loader outranks it, but for anything else it is the only candidate and the load
    recurses instead of falling back to shellcode. It declines while this is set.
    """
    return _loading_buffer


@contextmanager
def wait_box(message: str) -> Iterator[None]:
    """Show IDA's wait box around a long operation; nothing is shown in batch mode."""
    if is_batch_mode():
        yield
        return
    ida_kernwin.show_wait_box(f"HIDECANCEL\n{message}")
    try:
        yield
    finally:
        ida_kernwin.hide_wait_box()


def get_options() -> LoadOptions:
    """Read the ``-Ovtloader:...`` command line options.

    Raises:
        OptionsError: the option string is malformed.
    """
    return LoadOptions.from_plugin_options(
        ida_loader.get_plugin_options(PLUGIN_OPTIONS_NAME) or ""
    )


def get_database_extension() -> str:
    return ".i64" if ida_idaapi.BADADDR == 0xFFFFFFFFFFFFFFFF else ".idb"


def set_database_names(filename: str, database_dir: Path) -> None:
    """Name the database after the downloaded buffer instead of the input file.

    The root filename always changes. The IDB path only changes in interactive mode,
    so that headless callers keep the output path they chose; it then goes into
    ``database_dir``.

    Raises:
        UserCancelled: the target IDB exists and the user declined to overwrite it.
    """
    input_dir = Path(ida_loader.get_path(ida_loader.PATH_TYPE_CMD)).parent
    ida_nalt.set_root_filename(str(input_dir / filename))

    if is_batch_mode():
        return

    idb_path = database_dir / (filename + get_database_extension())
    if idb_path.exists():
        answer = ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_YES, f"{idb_path} already exists. Overwrite it?"
        )
        if answer != ida_kernwin.ASKBTN_YES:
            raise UserCancelled("user declined to overwrite the existing database")
    ida_loader.set_path(ida_loader.PATH_TYPE_IDB, str(idb_path))


def load_as_shellcode(buffer: bytes, bitness: int) -> None:
    """Map the buffer at address 0 as a single code segment for the x86 family."""
    ida_idp.set_processor_type(SHELLCODE_PROCESSOR, ida_idp.SETPROC_LOADER)
    ida_ida.inf_set_app_bitness(bitness)
    seg = ida_segment.segment_t()
    seg.start_ea = 0
    seg.end_ea = len(buffer)
    seg.bitness = 2 if bitness == 64 else 1
    seg.sel = ida_segment.setup_selector(0)
    if not ida_segment.add_segm_ex(
        seg, SHELLCODE_SEGMENT, "CODE", ida_segment.ADDSEG_OR_DIE
    ):
        raise LoadError("cannot create shellcode segment")
    ida_loader.mem2base(buffer, 0, -1)
    ida_entry.add_entry(0, 0, "start", True)


def confirm_shellcode_fallback(options: LoadOptions) -> int:
    """Decide whether and how to load an unrecognized buffer. Returns the bitness to use.

    Raises:
        UserCancelled: the user declined.
    """
    if is_batch_mode():
        return options.bitness
    answer = ida_kernwin.ask_yn(
        ida_kernwin.ASKBTN_YES,
        "No IDA loader recognizes this file.\nLoad it as raw x86 shellcode at address 0?",
    )
    if answer != ida_kernwin.ASKBTN_YES:
        raise UserCancelled("user declined shellcode mode")
    answer = ida_kernwin.ask_buttons(
        "64-bit", "32-bit", "Cancel", ida_kernwin.ASKBTN_YES, "Shellcode bitness?"
    )
    if answer == ida_kernwin.ASKBTN_YES:
        return 64
    if answer == ida_kernwin.ASKBTN_NO:
        return 32
    raise UserCancelled("user cancelled shellcode bitness selection")


def get_database_filetype(loader: LoaderInfo) -> int:
    """The ``filetype_t`` IDA's file dialog records for ``loader``; script loaders report 1 and map to f_LOADER."""
    return ida_ida.f_LOADER if loader.filetype == 1 else loader.filetype


def load_buffer_into_ida(
    buffer: bytes,
    filename: str,
    neflags: int,
    options: LoadOptions,
    database_dir: Path,
) -> LoadResult:
    """Load ``buffer`` into the current database using IDA's own file format loaders.

    The buffer never touches the disk. When no loader recognizes it, the buffer is
    mapped as shellcode instead. Must be called from within a loader's ``load_file``.
    Interactively the database is written to ``database_dir``.

    Raises:
        LoadError: the buffer is empty or an archive, or the chosen loader failed.
        UserCancelled: the user aborted one of the prompts.
        KernelError: the IDA kernel library cannot be bound.
    """
    if not buffer:
        raise LoadError("buffer is empty")

    set_database_names(filename, database_dir)
    kernel = IdaKernel.from_idadir()

    global _loading_buffer
    _loading_buffer = True
    try:
        return _load(kernel, buffer, filename, neflags, options)
    finally:
        _loading_buffer = False


def _load(
    kernel: IdaKernel, buffer: bytes, filename: str, neflags: int, options: LoadOptions
) -> LoadResult:
    with (
        kernel.bytearray_linput(buffer) as li,
        kernel.loaders_list(li, filename) as loaders,
    ):
        logger.debug("candidate loaders: %s", [e.format_name for e in loaders.entries])

        if not loaders.entries:
            bitness = confirm_shellcode_fallback(options)
            logger.info(
                "no loader recognized %s, loading as %d-bit shellcode",
                filename,
                bitness,
            )
            load_as_shellcode(buffer, bitness)
            return LoadResult(
                filename=filename, loader=None, filetype=ida_ida.inf_get_filetype()
            )

        best = loaders.best
        if best.is_archive:
            raise LoadError(
                f"{filename} is an archive ({best.format_name}); vtloader cannot open archives in memory"
            )

        logger.info("loading %s with %s", filename, best.format_name)
        ida_ida.inf_set_filetype(get_database_filetype(best))
        if not kernel.load_nonbinary_file(filename, li, neflags, loaders):
            raise LoadError(f"IDA loader {best.format_name!r} failed on {filename}")
        return LoadResult(
            filename=filename, loader=best, filetype=ida_ida.inf_get_filetype()
        )
