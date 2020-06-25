import idc
import idautils


def enum_segments():
    for segstart in idautils.Segments():
        segend = idc.get_segm_end(segstart)
        segname = idc.get_segm_name(segstart)
        yield segstart, segend, segname


def find_pointers(start, end):
    for va in range(start, end-0x4):
        ptr = idc.get_wide_dword(va)
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


CACHED_STRINGS = list(idautils.Strings())
def is_in_string(va):
    for s in CACHED_STRINGS:
        if s.ea <= va < s.ea + s.length:
            return True
    return False


def is_defined(va):
    pass


def is_unknown(va):
    return ida_bytes.is_unknown(idc.get_full_flags(va))


def main():
    for segstart, segend, segname in enum_segments():
        if segname not in ('.text', '.data'):
            continue

        for src, dst in find_pointers(segstart, segend):
            if is_code(src):
                # ignore instructions like:
                #
                #     call    ds:__vbaGenerateBoundsError
                #print('code pointer: 0x%x -> 0x%x' % (src, dst))
                continue

            if is_in_string(src):
                # for example, the following contains 0x444974 (a common valid offset):
                #
                #     text:004245B0 aRequestid    db 'requestID',
                #
                # enable or disable this behavior as you wish
                print('string pointer: 0x%x -> 0x%x' % (src, dst))
                pass
                #continue

            print('pointer from 0x%x to 0x%x' % (src, dst))

            if is_unknown(dst):
                print('destination unknown, making byte: 0x%x' % (dst))
                ida_bytes.create_data(dst, FF_BYTE, 1, ida_idaapi.BADADDR)

            elif is_head(dst):
                # things are good
                pass

            else:
                # need to undefine head, and make byte
                head_va = get_head(dst)
                print('destination overlaps with head: 0x%x' % (head_va))
                ida_bytes.del_items(head_va, dst - head_va)
                ida_bytes.create_data(head_va, FF_BYTE, 1, ida_idaapi.BADADDR)
                ida_bytes.create_data(dst, FF_BYTE, 1, ida_idaapi.BADADDR)

            ida_bytes.del_items(src, 4)
            ida_bytes.create_data(src, FF_DWORD, 4, ida_idaapi.BADADDR)
            # this doesn't seem to always work :-(
            idc.op_plain_offset(src, -1, 0)


if __name__ == '__main__':
    main()
