import ida_typeinf
import ida_funcs
import ida_xref
import idautils

enum_name = "_FILE_INFORMATION_CLASS"

til = ida_typeinf.get_idati()
tif = til.get_named_type(enum_name)

print(f"Enum: {enum_name} (tid: {tif.get_tid():X})")
for idx, edm in enumerate(tif.iter_enum()):
    print(f"  {edm.name} = 0x{edm.value:x} (tid: {edm.get_tid():X})")
    tid = edm.get_tid()
    if tid == ida_idaapi.BADADDR:
        continue

    # Marking an operand as an enum creates a dr_S (0x6) xref 
    # FROM instruction TO enum member's tid
    for xref in idautils.XrefsTo(tid, ida_xref.XREF_EA):
        # ida_xref.XREF_EA: return only program addresses
        # ida_xref.XREF_TID: return only type ids. 
        #
        # XREF_EA and XREF_TID are exclusive, only one of them can be specified
    
        func_name = ida_funcs.get_func_name(xref.frm) or f"sub_{xref.frm:X}"
        print(f"    - {xref.frm:X} in {func_name} (type: {xref.type})")
