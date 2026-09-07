"""IDA loader: pick a member of a ZIP archive and load it without extracting to disk."""

import logging

import ida_kernwin

from memloader import archive
from memloader.core import (
    UserCancelled,
    get_options,
    is_batch_mode,
    load_buffer_into_ida,
)
from memloader.options import DEFAULT_PASSWORD, LoadOptions

logger = logging.getLogger(__name__)

FORMAT_NAME = "Memloader ZIP"


def read_all(li) -> bytes:
    li.seek(0)
    return li.read(li.size())


def accept_file(li, filename):
    li.seek(0)
    if not archive.has_zip_magic(li.read(4)):
        return 0
    try:
        members = archive.get_members(read_all(li))
    except archive.ArchiveError:
        return 0
    if not members:
        return 0
    return FORMAT_NAME


class MemberChooser(ida_kernwin.Choose):
    def __init__(self, members: list[archive.Member]):
        super().__init__(
            "Memloader: choose the file to load",
            [
                ["Name", ida_kernwin.Choose.CHCOL_PATH | 50],
                ["Size", ida_kernwin.Choose.CHCOL_DEC | 12],
                ["Encrypted", 10],
            ],
            flags=ida_kernwin.Choose.CH_MODAL,
        )
        self.members = members

    def OnGetSize(self):
        return len(self.members)

    def OnGetLine(self, n):
        m = self.members[n]
        return [m.name, str(m.size), "yes" if m.encrypted else ""]


def choose_member(
    members: list[archive.Member], options: LoadOptions
) -> archive.Member:
    """Pick the member to load from the options in batch mode, or via a chooser otherwise.

    Raises:
        ArchiveError: the requested member does not exist.
        UserCancelled: the chooser was closed without a selection.
    """
    if is_batch_mode() or options.member is not None:
        return archive.select_member(members, options.member)
    if len(members) == 1:
        return members[0]
    index = MemberChooser(members).Show(modal=True)
    if index < 0:
        raise UserCancelled("no archive member selected")
    return members[index]


def choose_password(member: archive.Member, options: LoadOptions) -> str | None:
    if not member.encrypted:
        return None
    if is_batch_mode():
        return options.password
    password = ida_kernwin.ask_str(
        DEFAULT_PASSWORD, ida_kernwin.HIST_IDENT, f"Password for {member.basename}"
    )
    if password is None:
        raise UserCancelled("no password entered")
    return password


def load_file(li, neflags, format):
    data = read_all(li)
    options = get_options()
    members = archive.get_members(data)
    member = choose_member(members, options)
    password = choose_password(member, options)
    buffer = archive.extract_member(data, member, password)
    logger.info("extracted %s (%d bytes) from archive", member.name, len(buffer))
    load_buffer_into_ida(buffer, member.basename, neflags, options)
    return 1
