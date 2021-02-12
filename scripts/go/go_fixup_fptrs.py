"""
when IDA's auto-discovery of functions in 64-bit Windows Go executables fails,
scan for global (.rdata) pointers into the code section (.text) and assume these are function pointers.
"""
import idc
import ida_name
import ida_auto
import ida_bytes
import idautils


def enum_segments():
    for segstart in idautils.Segments():
        segend = idc.get_segm_end(segstart)
        segname = idc.get_segm_name(segstart)
        yield segstart, segend, segname


def find_pointers(start, end):
    for va in range(start, end-0x8):
        ptr = ida_bytes.get_qword(va)
        if idc.get_segm_start(ptr) != idc.BADADDR:
            yield va, ptr, 8
        ptr = ida_bytes.get_dword(va)
        if idc.get_segm_start(ptr) != idc.BADADDR:
            yield va, ptr, 4


def is_head(va):
    return ida_bytes.is_head(idc.get_full_flags(va))


def get_head(va):
    if is_head(va):
        return va
    else:
        return idc.prev_head(va)


def is_code(va):
    if is_head(va):
        flags = idc.get_full_flags(va)
        return ida_bytes.is_code(flags)
    else:
        head = get_head(va)
        return is_code(head)


def is_unknown(va):
    return ida_bytes.is_unknown(idc.get_full_flags(va))


def main():
    for segstart, segend, segname in enum_segments():
        if segname not in ('.rdata', 'UPX1'):
            continue

        print(segname)
        for src, dst, size in find_pointers(segstart, segend):
            if idc.get_segm_name(dst) not in (".text", "UPX0"):
                continue

            if is_code(dst):
                continue

            print("new function pointer: 0x%x -> 0x%x" % (src, dst))

            ida_auto.auto_make_code(dst)
            ida_auto.auto_make_proc(dst)

            ida_bytes.del_items(src, size)
            ida_bytes.create_data(src, idc.FF_QWORD if size == 8 else idc.FF_DWORD, size, idc.BADADDR)
            # this doesn't seem to always work :-(
            idc.op_plain_offset(src, -1, 0)
            ida_name.set_name(src, "j_%s_%x" % (src, dst))

if __name__ == '__main__':
    main()
