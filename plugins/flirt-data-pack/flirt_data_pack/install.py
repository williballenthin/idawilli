"""Maintain symlinks that make IDA discover the shipped FLIRT signatures.

IDA searches ``$IDAUSR/sig/<procname>/`` for ``.sig`` files. Both the name-based
lookup (``plan_to_apply_idasgn``) and the UI chooser (``build_list``) scan each
directory flat, without recursing into subdirectories. This module links each
signature from the plugin's ``sigs/<proc>/`` directory into the user sig directory,
prefixing the link name with the plugin name to avoid collisions between plugins.

For example, ``sigs/pc/dummy.sig`` becomes
``~/.idapro/sig/pc/flirt_data_pack_dummy.sig``.

Symbolic links are preferred; on Windows without symlink permission a hard link
is made instead.
"""

import logging
import os
from collections.abc import Sequence
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)

PLUGIN_NAME = "flirt_data_pack"
LINK_PREFIX = f"{PLUGIN_NAME}_"


class LinkKind(Enum):
    SYMLINK = "symlink"
    HARDLINK = "hardlink"


DEFAULT_LINK_KINDS: tuple[LinkKind, ...] = (
    (LinkKind.SYMLINK, LinkKind.HARDLINK) if os.name == "nt" else (LinkKind.SYMLINK,)
)


def link_name_for(sig_name: str) -> str:
    return f"{LINK_PREFIX}{sig_name}"


def get_sig_sources(plugin_root: Path, proc: str) -> list[Path]:
    sig_dir = plugin_root / "sigs" / proc
    if not sig_dir.is_dir():
        return []
    return sorted(sig_dir.glob("*.sig"))


def get_procs(plugin_root: Path) -> list[str]:
    sigs_dir = plugin_root / "sigs"
    if not sigs_dir.is_dir():
        return []
    return sorted(d.name for d in sigs_dir.iterdir() if d.is_dir())


def is_our_link(path: Path, plugin_root: Path) -> bool:
    """True when ``path`` is a link we created: its name starts with our prefix
    and it points into ``plugin_root``, or is a hard link of one of our sig files.
    """
    if not path.name.startswith(LINK_PREFIX):
        return False
    if path.is_symlink():
        target = Path(os.readlink(path))
        return target.is_relative_to(plugin_root.resolve())
    if not path.is_file():
        return False
    for source in plugin_root.resolve().glob("sigs/*/*.sig"):
        try:
            if os.path.samefile(path, source):
                return True
        except OSError:
            continue
    return False


def is_current_link(path: Path, target: Path) -> bool:
    if path.is_symlink():
        return Path(os.readlink(path)) == target
    try:
        return path.is_file() and os.path.samefile(path, target)
    except OSError:
        return False


def create_link(path: Path, target: Path, kinds: Sequence[LinkKind]) -> LinkKind:
    """Link ``path`` to ``target`` with the first kind in ``kinds`` that the system permits.

    Raises:
        OSError: no kind could be created; the last error is raised.
    """
    error: OSError | None = None
    for kind in kinds:
        try:
            if kind is LinkKind.SYMLINK:
                path.symlink_to(target)
            else:
                os.link(target, path)
            return kind
        except OSError as e:
            logger.info("cannot create %s %s -> %s: %s", kind.value, path, target, e)
            error = e
    assert error is not None
    raise error


def remove_stale_links(sig_dir: Path, plugin_root: Path) -> None:
    """Remove our prefixed links in ``sig_dir`` whose target no longer exists."""
    for path in sig_dir.glob(f"{LINK_PREFIX}*.sig"):
        if not path.is_symlink():
            continue
        if not path.exists() and is_our_link(path, plugin_root):
            logger.info("removing stale sig link %s", path)
            path.unlink()


def install_sig_links(
    sig_dir: Path,
    plugin_root: Path,
    proc: str,
    kinds: Sequence[LinkKind] = DEFAULT_LINK_KINDS,
) -> list[Path]:
    """Create links in ``sig_dir`` for all ``.sig`` files shipped for ``proc``.

    Each link is named ``flirt_data_pack_<original>.sig`` so that different plugins
    can ship signatures without colliding. A link that already points at the right
    target is left untouched. Returns the paths of the installed links.

    Raises:
        OSError: the directory cannot be created or a link cannot be made.
    """
    sig_dir.mkdir(parents=True, exist_ok=True)
    remove_stale_links(sig_dir, plugin_root)

    sources = get_sig_sources(plugin_root, proc)
    installed: list[Path] = []
    for source in sources:
        target = source.resolve()
        path = sig_dir / link_name_for(source.name)
        if is_current_link(path, target):
            logger.debug("sig link %s is current", path)
            installed.append(path)
            continue
        if path.is_symlink() and path.name.startswith(LINK_PREFIX):
            path.unlink()
        elif path.exists():
            logger.warning(
                "not replacing %s: it was not created by %s", path, PLUGIN_NAME
            )
            continue
        kind = create_link(path, target, kinds)
        logger.info("created %s %s -> %s", kind.value, path, target)
        installed.append(path)
    return installed
