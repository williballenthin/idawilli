import idc
import idautils


def enum_segments():
    for segstart in idautils.Segments():
        segend = idc.SegEnd(segstart)
        segname = idc.SegName(segstart)
        yield segstart, segend, segname


def find_pointers(start, end):
    for va in range(start, end-0x4):
        ptr = idc.Dword(va)
        if idc.SegStart(ptr) == idc.BADADDR:
            continue

        yield va, ptr


def is_head(va):
    return idc.isHead(idc.GetFlags(va))


def get_head(va):
    if is_head(va):
        return va
    else:
        return idc.PrevHead(va)


def is_code(va):
    if is_head(va):
        flags = idc.GetFlags(va)
        return idc.isCode(flags)
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
    return idc.isUnknown(idc.GetFlags(va))


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
                idc.MakeByte(dst)

            elif is_head(dst):
                # things are good
                pass

            else:
                # need to undefine head, and make byte
                head_va = get_head(dst)
                print('destination overlaps with head: 0x%x' % (head_va))
                idc.MakeUnkn(head_va, dst - head_va)
                idc.MakeByte(head_va)
                idc.MakeByte(dst)

            idc.MakeUnkn(src, 4)
            idc.MakeDword(src)
            # this doesn't seem to always work :-(
            idc.OpOffset(src, 0)


if __name__ == '__main__':
    main()
