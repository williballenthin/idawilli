import idc
import idautils
import ida_offset

reftype = ida_offset.get_default_reftype(next(idautils.Segments()))

for segea in idautils.Segments():
    for head in idautils.Heads(idc.SegStart(segea), idc.SegEnd(segea)):
        if not idc.isCode(idc.GetFlags(head)):
            continue

        for i in range(2):
            if idc.SegStart(idc.GetOperandValue(head, i)) == idc.BADADDR:
                continue
            ida_offset.op_offset(head, i, reftype)

print("ok")
