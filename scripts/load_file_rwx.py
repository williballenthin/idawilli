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
        buf = tuple(map(ord, f.read()))
        
    if len(buf) == 0:
        print("empty file, cancelling")
        return
        
    size = idawilli.align(len(buf), 0x1000)
    print("size: 0x%x" % (len(buf)))
    print("aligned size: 0x%x" % (size))
    
    addr = idawilli.dbg.allocate_rwx(size)
    print("allocated 0x%x bytes at 0x%x" % (size, addr))
        
    idawilli.dbg.patch_bytes(addr, buf)
    print("patched file to 0x%x" % (addr))

    print("ok")
    
main()