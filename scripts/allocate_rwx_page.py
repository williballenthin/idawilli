import ida_kernwin

import idawilli.dbg


def main():
    size = ida_kernwin.ask_long(0x1000, "size of allocation")
    if not size:
        return

    ptr = idawilli.dbg.allocate_rwx(size)
    print('allocated 0x%x bytes at 0x%x' % (size, ptr))


main()