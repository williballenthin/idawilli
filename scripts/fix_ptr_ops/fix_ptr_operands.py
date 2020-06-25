import idc
import idautils
import ida_offset

reftype = ida_offset.get_default_reftype(next(idautils.Segments()))

for segea in idautils.Segments():
    for head in idautils.Heads(idc.get_segm_start(segea), idc.get_segm_end(segea)):
        if not ida_bytes.is_code(ida_bytes.get_full_flags(head)):
            continue

        for i in range(2):
            if idc.get_segm_start(idc.get_operand_value(head, i)) == idc.BADADDR:
                continue
            ida_offset.op_offset(head, i, reftype)

print("ok")
