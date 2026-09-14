"""Mapping from file type to signatures that should be auto-applied.

The mapping uses file type constants that match ``ida_ida.f_*`` values. The
processor is not checked: IDA searches ``sig/<current_proc>/`` automatically,
so a signature shipped only under ``sigs/pc/`` is never found when the active
processor is ARM.
"""

from flirt_data_pack.install import LINK_PREFIX

F_PE = 11
F_ELF = 18
F_MACHO = 25

AUTO_APPLY: dict[int, list[str]] = {
    F_PE: ["dummy"],
    F_ELF: ["dummy"],
}


def installed_name(base: str) -> str:
    """The name to pass to ``plan_to_apply_idasgn`` for a shipped signature.

    Strips ``.sig`` from the prefixed link name, since
    ``plan_to_apply_idasgn`` appends it during lookup.
    """
    return f"{LINK_PREFIX}{base}"


def get_signatures_for(filetype: int) -> list[str]:
    """Return installed signature names to auto-apply for the given file type."""
    return [installed_name(b) for b in AUTO_APPLY.get(filetype, [])]
