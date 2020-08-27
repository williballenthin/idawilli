import idc
import ida_kernwin

import idawilli
import idawilli.dbg

# removeme
import ida_idaapi
ida_idaapi.require('idawilli')
ida_idaapi.require('idawilli.dbg')


def main():
    path = ida_kernwin.ask_file(False, "*", "file to load")
    if not path:
        return
        
    with open(path, "rb") as f:
        buf = tuple(f.read())
        
    if len(buf) == 0:
        print("empty file, cancelling")
        return
        
    size = idawilli.align(len(buf), 0x1000)
    print("size: 0x%x" % (len(buf)))
    print("aligned size: 0x%x" % (size))
        
    addr = ida_kernwin.ask_addr(idc.get_screen_ea(), "location to write")
    if not addr:
        return
        
    idawilli.dbg.patch_bytes(addr, buf)

    print("ok")
    
main()