import ida_loader
import ida_idaapi
import ida_kernwin


def main():
    offset = ida_kernwin.ask_addr(0x0, "file offset")
    if not offset:
        return

    ea = ida_loader.get_fileregion_ea(offset)
    if ea == ida_idaapi.BADADDR:
        print('error: EA for file offset not found')
        return

    print('EA for file offset: 0x%x' % (ea))
    ida_kernwin.jumpto(ea)


main()
