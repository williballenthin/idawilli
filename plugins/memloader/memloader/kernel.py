"""Direct access to IDA kernel loader functions that IDAPython does not expose.

``build_loaders_list`` and ``load_nonbinary_file`` are exported from the IDA kernel
library with C linkage but are excluded from the SWIG bindings. This module calls
them through ``ctypes`` on the kernel library that is already loaded in the process.
"""

import ctypes
import logging
import platform
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import ida_diskio
import ida_idaapi

logger = logging.getLogger(__name__)

LIF_ARCHLDR = 0x0001


class KernelError(RuntimeError):
    pass


class _qstring(ctypes.Structure):
    _fields_ = [
        ("array", ctypes.c_char_p),
        ("n", ctypes.c_size_t),
        ("alloc", ctypes.c_size_t),
    ]

    def get(self) -> str:
        return (self.array or b"").decode("utf-8", errors="replace")


class _load_info_t(ctypes.Structure):
    pass


_load_info_t._fields_ = [
    ("next", ctypes.POINTER(_load_info_t)),
    ("dllname", _qstring),
    ("ftypename", _qstring),
    ("processor", _qstring),
    ("ftype", ctypes.c_int32),
    ("loader_flags", ctypes.c_uint32),
    ("lflags", ctypes.c_uint32),
    ("pri", ctypes.c_int32),
]


@dataclass(frozen=True)
class LoaderInfo:
    """One candidate loader for an input file, as reported by the IDA kernel."""

    dllname: str
    format_name: str
    processor: str
    filetype: int
    loader_flags: int
    lflags: int
    priority: int

    @property
    def is_archive(self) -> bool:
        return bool(self.lflags & LIF_ARCHLDR)

    @classmethod
    def from_struct(cls, node: _load_info_t) -> "LoaderInfo":
        return cls(
            dllname=node.dllname.get(),
            format_name=node.ftypename.get(),
            processor=node.processor.get(),
            filetype=node.ftype,
            loader_flags=node.loader_flags,
            lflags=node.lflags,
            priority=node.pri,
        )


@dataclass
class Linput:
    """A kernel ``linput_t`` backed by a Python buffer that must outlive it."""

    pointer: int
    _buffer: ctypes.Array


@dataclass
class LoaderList:
    """A kernel ``load_info_t`` linked list and its decoded entries."""

    pointer: int
    entries: list[LoaderInfo]

    @property
    def best(self) -> LoaderInfo:
        return self.entries[0]


def get_kernel_library_path() -> Path:
    system = platform.system()
    is_ea64 = ida_idaapi.BADADDR == 0xFFFFFFFFFFFFFFFF
    base = "ida" if is_ea64 else "ida32"
    if system == "Windows":
        name = f"{base}.dll"
    elif system == "Darwin":
        name = f"lib{base}.dylib"
    else:
        name = f"lib{base}.so"
    return Path(ida_diskio.idadir("")) / name


class IdaKernel:
    def __init__(self, lib: ctypes.CDLL):
        self._lib = lib
        lib.create_bytearray_linput.restype = ctypes.c_void_p
        lib.create_bytearray_linput.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        lib.close_linput.restype = None
        lib.close_linput.argtypes = [ctypes.c_void_p]
        lib.build_loaders_list.restype = ctypes.POINTER(_load_info_t)
        lib.build_loaders_list.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.free_loaders_list.restype = None
        lib.free_loaders_list.argtypes = [ctypes.c_void_p]
        lib.load_nonbinary_file.restype = ctypes.c_bool
        lib.load_nonbinary_file.argtypes = [
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_ushort,
            ctypes.c_void_p,
        ]

    @classmethod
    def from_idadir(cls) -> "IdaKernel":
        """Bind to the IDA kernel library of the running IDA instance.

        Raises:
            KernelError: the library cannot be located or lacks the expected exports.
        """
        path = get_kernel_library_path()
        if not path.exists():
            raise KernelError(f"IDA kernel library not found at {path}")
        try:
            lib = ctypes.CDLL(str(path))
            return cls(lib)
        except (OSError, AttributeError) as e:
            raise KernelError(f"cannot bind to IDA kernel library {path}: {e}") from e

    @contextmanager
    def bytearray_linput(self, buffer: bytes) -> Iterator[Linput]:
        cbuf = ctypes.create_string_buffer(buffer, len(buffer))
        pointer = self._lib.create_bytearray_linput(cbuf, len(buffer))
        if not pointer:
            raise KernelError("create_bytearray_linput failed")
        try:
            yield Linput(pointer=pointer, _buffer=cbuf)
        finally:
            self._lib.close_linput(pointer)

    @contextmanager
    def loaders_list(self, li: Linput, filename: str) -> Iterator[LoaderList]:
        """Enumerate the loaders that accept the input, best candidate first. Empty when none match."""
        head = self._lib.build_loaders_list(li.pointer, filename.encode("utf-8"))
        entries = []
        node = head
        while node:
            entries.append(LoaderInfo.from_struct(node.contents))
            node = node.contents.next
        pointer = ctypes.cast(head, ctypes.c_void_p).value or 0
        try:
            yield LoaderList(pointer=pointer, entries=entries)
        finally:
            if pointer:
                self._lib.free_loaders_list(pointer)

    def load_nonbinary_file(
        self, filename: str, li: Linput, neflags: int, loaders: LoaderList
    ) -> bool:
        """Run the best loader from ``loaders`` on the input and return whether it succeeded."""
        return bool(
            self._lib.load_nonbinary_file(
                filename.encode("utf-8"), li.pointer, b".", neflags, loaders.pointer
            )
        )
