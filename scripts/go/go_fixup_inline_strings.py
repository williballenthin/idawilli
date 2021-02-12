"""
create and annotate references to strings in 64-bit Windows Go executables.

expect to see the assembly pattern:

  lea reg, $string
  mov [stack], reg
  mov [stack], $size
"""
import idc
import ida_ua
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
        if idc.get_segm_start(ptr) == idc.BADADDR:
            continue

        yield va, ptr


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


def main():
    for segstart, segend, segname in enum_segments():
        for head in idautils.Heads(segstart, segend):
            if not is_code(head):
                continue

            # pattern:
            #
            #   lea     rax, unk_6BDF88
            #   mov     [rsp+0], rax
            #   mov     qword ptr [rsp+8], 40h 
            if ida_ua.ua_mnem(head) != "lea":
                continue

            next_head = ida_bytes.next_head(head, idc.BADADDR)
            if ida_ua.ua_mnem(next_head) != "mov":
                continue

            next_head2 = ida_bytes.next_head(next_head, idc.BADADDR)
            if ida_ua.ua_mnem(next_head2) != "mov":
                continue

            dst = idc.get_operand_value(head, 1)
            if idc.get_segm_name(dst) not in (".rdata", "UPX1"):
                continue

            size = idc.get_operand_value(next_head2, 1)

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

            print("string pointer: 0x%x -> 0x%x: %s" % (head, dst, s))
            ida_bytes.del_items(dst, 1)
            ida_bytes.create_data(dst, idc.FF_BYTE, 1, idc.BADADDR)
            ida_bytes.set_cmt(dst, s, True)
            ida_name.set_name(dst, "s_%x" % (dst))

if __name__ == '__main__':
    main()
