'''
scan all pointers in the segment that contains EA,
checking if they point to an external name.
if so, rename the pointer.

this is intended to be used during debugging of a packed sample.
'''
import idc
import ida_name
import ida_bytes
import ida_segment


# TODO: arch
psize = 4

def get_ptr(ea):
    # TODO: arch
	return ida_bytes.get_dword(ea)
	
    
def make_ptr(ea):
    # TODO: arch
    ida_bytes.del_items(ea, 0, psize)
    return ida_bytes.create_dword(ea, psize)
	
    
def enum_ptrs(start, end):
	for ea in range(start, end, psize):
		yield (ea, get_ptr(ea))
		
		
def enum_segment_ptrs(ea):
	seg = ida_segment.getseg(ea)
	for (ea, ptr) in enum_ptrs(seg.start_ea, seg.end_ea):
		yield (ea, ptr)
		


for ea, ptr in enum_segment_ptrs(idc.ScreenEA()):
    name = ida_name.get_name(ptr)
    
    if not name:
        continue
        
    if name.startswith('loc_'):
        continue    
       
    print(hex(ea) + ': ' + name)
    
    make_ptr(ea)
    ida_name.set_name(ea, name)
