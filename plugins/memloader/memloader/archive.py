"""ZIP archive inspection and extraction from an in-memory buffer."""

import io
import logging
import zipfile
from dataclasses import dataclass

logger = logging.getLogger(__name__)

ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06")
FLAG_ENCRYPTED = 0x1


class ArchiveError(ValueError):
    pass


class BadPassword(ArchiveError):
    pass


@dataclass(frozen=True)
class Member:
    name: str
    size: int
    encrypted: bool

    @classmethod
    def from_zipinfo(cls, info: zipfile.ZipInfo) -> "Member":
        return cls(
            name=info.filename,
            size=info.file_size,
            encrypted=bool(info.flag_bits & FLAG_ENCRYPTED),
        )

    @property
    def basename(self) -> str:
        return self.name.rstrip("/").rsplit("/", 1)[-1]


def has_zip_magic(head: bytes) -> bool:
    return head.startswith(ZIP_MAGICS)


def get_members(data: bytes) -> list[Member]:
    """List the regular files inside a ZIP buffer, in archive order.

    Raises:
        ArchiveError: the buffer is not a valid ZIP archive.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return [Member.from_zipinfo(i) for i in zf.infolist() if not i.is_dir()]
    except zipfile.BadZipFile as e:
        raise ArchiveError(str(e)) from e


def select_member(members: list[Member], name: str | None) -> Member:
    """Pick the member called ``name``, or the first member when ``name`` is None.

    A member matches on its full archive path or on its basename.

    Raises:
        ArchiveError: the archive has no members or ``name`` matches none of them.
    """
    if not members:
        raise ArchiveError("archive contains no files")
    if name is None:
        return members[0]
    for member in members:
        if member.name == name or member.basename == name:
            return member
    raise ArchiveError(f"no member named {name!r} in archive")


def extract_member(data: bytes, member: Member, password: str | None) -> bytes:
    """Read one member of a ZIP buffer into memory.

    Raises:
        BadPassword: the member is encrypted and the password is missing or wrong.
        ArchiveError: the member cannot be decompressed.
    """
    pwd = password.encode() if password is not None else None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return zf.read(member.name, pwd=pwd)
    except RuntimeError as e:
        if "password" in str(e).lower() or "encrypted" in str(e).lower():
            raise BadPassword(f"cannot decrypt {member.name!r}: {e}") from e
        raise ArchiveError(str(e)) from e
    except (zipfile.BadZipFile, NotImplementedError) as e:
        raise ArchiveError(str(e)) from e
