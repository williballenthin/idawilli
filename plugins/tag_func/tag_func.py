import logging
from typing import Iterator, List, Optional, Tuple

import ida_name
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_dirtree

from ida_dirtree import dirtree_t

logger = logging.getLogger("tag_func")


def dirtree_find(dirtree: dirtree_t, pattern) -> Iterator[ida_dirtree.dirtree_cursor_t]:
    """
    enumerate the matches for the given pattern against the given dirtree.
    this is just a Pythonic helper over the SWIG-generated routines.
    """
    # pattern format:
    #  "*" for all in current directory, does not recurse
    #  "/" for root directory
    #  "/sub_410000" for item by name
    #  "/foo" for directory by name, no trailing slash
    #  "/foo/*" for path prefix
    #      does not recurse beyond the prefix path
    #      matches "/foo/sub_401000" and but not "/foo/bar/sub_4010005"
    #  "/foo/sub_*" for path prefix (matches "/foo/sub_401000")
    #  "*main" for suffix (matches "/_main" because leading / is implied)
    #  "*mai*" for substring (matches "/_main" and "/_main_0" because leading / is implied)
    #
    #  wildcards only seem to match within path components
    #    does *not* work:
    #      "/*/sub_401000"
    #      "*/sub_401000"
    #      "*"
    #
    # to search by name, i guess use pattern "*" and check get_entry_name
    ff = ida_dirtree.dirtree_iterator_t()
    ok = dirtree.findfirst(ff, pattern)
    while ok:
        yield ff.cursor
        ok = dirtree.findnext(ff)


def dirtree_join(*parts: list[str]) -> str:
    return "/".join(parts)


def dirtree_walk(dirtree: dirtree_t, top: str) -> Iterator[Tuple[str, List[str], List[str]]]:
    """
    like os.walk over the given dirtree.

    yields tuples: (root, [dirs], [files])
    use dirtree_join(*parts) to join root and dir/file entry:

        # print all files
        for root, dirs, files in dirtree_walk(func_dir, "/"):
            for file in files:
                print(dirtree_join(root, file))
    """
    top = top.rstrip("/")
    directories = [top]

    while len(directories) > 0:
        directory = directories.pop(0)

        dirs = []
        files = []

        for cursor in dirtree_find(dirtree, f"{directory}/*"):
            dirent = dirtree.resolve_cursor(cursor)
            name = dirtree.get_entry_name(dirent)

            if dirent.isdir:
                dirs.append(name)
                directories.append(dirtree_join(directory, name))
            else:
                files.append(name)

        yield (directory, dirs, files)


def find_function_dirtree_path(va: int) -> Optional[str]:
    """
    given the address of a function
    find its absolute path within the function dirtree.
    """
    func_dir: dirtree_t = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)

    name = ida_name.get_name(va)
    if not name:
        return None

    for root, _, files in dirtree_walk(func_dir, "/"):
        for file in files:
            if file == name:
                return dirtree_join(root, file)

    return None


def dirtree_mkdirs(dirtree: dirtree_t, path: str):
    parts = path.split("/")

    for i in range(2, len(parts) + 1):
        prefix = "/".join(parts[:i])

        if not dirtree.isdir(prefix):
            e = dirtree.mkdir(prefix)
            if e != ida_dirtree.DTE_OK:
                logger.error("error: %s", ida_dirtree.dirtree_t_errstr(e))
                return e

    return ida_dirtree.DTE_OK


def set_tagged_func_cmt(tag: str, va: int, cmt: str, repeatable: bool):
    func = ida_funcs.get_func(va)
    existing = (ida_funcs.get_func_cmt(func, repeatable) or "").strip()

    prefix = f"{tag}: "
    line = f"{prefix}{cmt}"

    if prefix in existing:
        rest = existing.partition(prefix)[2].partition("\n")[0]
        new = existing.replace(f"{prefix}{rest}", line)
    elif existing == "":
        new = line
    else:
        new = existing + f"\n{line}"

    ida_funcs.set_func_cmt(func, new, repeatable)


def set_func_folder_cmt(va: int, folder: str):
    set_tagged_func_cmt("📁", va, folder, True)


def sync_func_folder_cmts():
    func_dir: dirtree_t = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    for root, _, files in dirtree_walk(func_dir, "/"):
        if root == "/" or root == "":
            continue

        tag = root.lstrip("/")
        for file in files:
            va = ida_name.get_name_ea(ida_idaapi.BADADDR, file)
            if va == ida_idaapi.BADADDR:
                continue

            set_func_folder_cmt(va, tag)


def main():
    va = ida_kernwin.get_screen_ea()
    f = ida_funcs.get_func(va)
    if not f:
        logger.error("function not found: 0x%x", va)
        return

    path = find_function_dirtree_path(f.start_ea)
    if not path:
        logger.error("function directory entry not found: 0x%x", f.start_ea)
        return

    func_dir: dirtree_t = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)

    dirent = func_dir.resolve_path(path)
    name = func_dir.get_entry_name(dirent)
    existing_tag = path[: -(len("/") + len(name))].lstrip("/")

    # ask_str(defval, hist, prompt) -> PyObject *
    # I'm not sure what "history id" does.
    tag = ida_kernwin.ask_str(existing_tag, 69, "tag:")
    if not tag:
        return

    tag_path = f"/{tag}"
    if not func_dir.isdir(tag_path):
        logger.info("creating tag: %s", tag)

        e = dirtree_mkdirs(func_dir, tag_path)
        if e != ida_dirtree.DTE_OK:
            logger.error("error: failed to create tag: %s", tag)
            return

    else:
        logger.debug("tag exists: %s", tag)

    src_path = path
    src_dirent = func_dir.resolve_path(src_path)
    src_name = func_dir.get_entry_name(src_dirent)

    dst_name = src_name
    dst_path = f"{tag_path}/{dst_name}"

    if src_path == dst_path:
        logger.info("skipping move to itself")
        return

    logger.info("moving %s from %s to %s", src_name, src_path, dst_path)
    e = func_dir.rename(src_path, dst_path)
    if e != ida_dirtree.DTE_OK:
        logger.error("error: %s", ida_dirtree.dirtree_t_errstr(e))
        return

    set_func_folder_cmt(f.start_ea, tag)


class TagFunctionPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_MULTI
    comment = "Quickly organize functions into tags via hotkey"
    help = "Quickly organize functions into tags via hotkey"
    wanted_name = "Tag Function"
    wanted_hotkey = "Z"

    def init(self):
        sync_func_folder_cmts()
        return ida_idaapi.PLUGIN_OK

    def run(self, _arg):
        main()
        return True


def PLUGIN_ENTRY():
    return TagFunctionPlugin()


if __name__ == "__main__":
    sync_func_folder_cmts()
    main()
