"""
find and annotate global references to string in 64-bit Windows Go executables.

expect to see the pattern:

    .rdata: qword ptr string -> .rdata
    .rdata: qword size
"""
import idc
import ida_name
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
        if segname not in ('.rdata', 'UPX1' ):
            continue

        for src, dst, psize in find_pointers(segstart, segend):
            if idc.get_segm_name(dst) not in (".rdata", "UPX0"):
                continue
                
            if psize == 8:
                size = ida_bytes.get_qword(src + 0x8)
            else:
                size = ida_bytes.get_dword(src + 0x4)
                
            if size > 0x100:
                continue
            if size <= 2:
                continue

            buf = ida_bytes.get_bytes(dst, size)
            if not buf:
                continue

            if b"\x00" in buf:
                continue

            try:
                s = buf.decode("ascii")
            except UnicodeDecodeError:
                continue

            print("string pointer: 0x%x -> 0x%x: %s" % (src, dst, s))

            ida_bytes.del_items(src, 1)
            ida_bytes.set_cmt(dst, s, True)

            # pointer
            ida_bytes.del_items(src, psize)
            ida_bytes.create_data(src, idc.FF_QWORD if size == 8 else idc.FF_DWORD, psize, idc.BADADDR)
            # this doesn't seem to always work :-(
            idc.op_plain_offset(src, -1, 0)
            ida_name.set_name(src, "s_%x" % (src))
            ida_bytes.set_cmt(src, s, True)

            # size
            ida_bytes.del_items(src + psize, psize)
            ida_bytes.create_data(src + psize, idc.FF_QWORD if size == 8 else idc.FF_DWORD, psize, idc.BADADDR)

if __name__ == '__main__':
    main()
