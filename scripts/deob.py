"""
search for and patch out known opaque predicates within IDA Pro workspaces.

just run the script and it will manipulate the open database.
therefore, you should probably create a backup first.
"""
import logging
from pprint import pprint

import ida_idp
import idautils
import ida_auto
import ida_bytes
import ida_segment


logger = logging.getLogger("deob")


def nop_region(ea, size):
    """replace the given range with NOPs"""
    logger.debug("nopping region from 0x%x size 0x%x", ea, size)

    for i in range(ea, ea + size):
        ida_bytes.del_items(i)

    for i in range(ea, ea + size):
        ida_bytes.patch_byte(i, 0x90)

    ida_auto.auto_make_code(ea)


def is_jump_plus_one(ea):
    """
    like:

        .text:00401089                 jmp     short loc_40108C
        .text:00401089 ; ---------------------------------------------------------------------------
        .text:0040108B                 db 0BAh ; º
        .text:0040108C ; ---------------------------------------------------------------------------
        .text:0040108C
        .text:0040108C loc_40108C:                             ; CODE XREF: .text:00401089↑j
        .text:0040108C                 mov     eax, 1
    """
    insn = idautils.DecodeInstruction(ea)
    if insn is None:
        logger.debug("0x%x: failed to decode instruction", ea)
        return False, None

    if insn.get_canon_mnem() != "jmp":
        return False, None

    next_ea = insn.ea + insn.size
    if insn.ops[0].addr != next_ea + 1:
        return False, None

    return True, insn.size + 1


def is_jmp_ret(ea):
    """
    like:

        .text:004010C9                 call    $+5
        .text:004010CE                 add     dword ptr [esp], 6
        .text:004010D2                 retn
        .text:004010D2 ; ---------------------------------------------------------------------------
        .text:004010D3                 db  7Dh ; }
        .text:004010D4 ; ---------------------------------------------------------------------------
        .text:004010D4                 mov     eax, 0
    """
    insn = idautils.DecodeInstruction(ea)
    if insn is None:
        return False, None

    if insn.get_canon_mnem() != "call":
        return False, None

    next_ea = insn.ea + insn.size
    if insn.ops[0].addr != next_ea:
        return False, None

    insn = idautils.DecodeInstruction(next_ea)
    if insn is None:
        return False, None

    if insn.get_canon_mnem() != "add":
        return False, None

    delta = insn.ops[1].value
    target = next_ea + delta

    next_ea = insn.ea + insn.size

    insn = idautils.DecodeInstruction(next_ea)
    if insn is None:
        return False, None

    if insn.get_canon_mnem() != "retn":
        return False, None

    return True, target - ea


def is_stc_jb(ea):
    """
    like:

        .text:00401042                 stc
        .text:00401043                 jb      short loc_401046
        .text:00401043 ; ---------------------------------------------------------------------------
        .text:00401045                 db 0B1h ; ±
        .text:00401046 ; ---------------------------------------------------------------------------
        .text:00401046
        .text:00401046 loc_401046:                             ; CODE XREF: .text:00401043↑j
        .text:00401046                 mov     eax, 0
    """
    insn = idautils.DecodeInstruction(ea)
    if insn is None:
        return False, None

    if insn.get_canon_mnem() != "stc":
        return False, None

    next_ea = insn.ea + insn.size

    insn = idautils.DecodeInstruction(next_ea)
    if insn is None:
        return False, None

    if insn.get_canon_mnem() != "jb":
        return False, None

    if insn.ops[0].addr != insn.ea + insn.size + 1:
        return False, None

    return True, 4


def is_clc_jnb(ea):
    """
    like:

        .text:0040139E                 clc
        .text:0040139F                 jnb     short loc_4013A2
        .text:0040139F ; ---------------------------------------------------------------------------
        .text:004013A1                 db  0Fh
        .text:004013A2 ; ---------------------------------------------------------------------------
        .text:004013A2
        .text:004013A2 loc_4013A2:                             ; CODE XREF: .text:0040139F↑j
        .text:004013A2                 mov     eax, 0x0
    """
    insn = idautils.DecodeInstruction(ea)
    if insn is None:
        return False, None

    if insn.get_canon_mnem() != "clc":
        return False, None

    next_ea = insn.ea + insn.size

    insn = idautils.DecodeInstruction(next_ea)
    if insn is None:
        return False, None

    if insn.get_canon_mnem() != "jnb":
        return False, None

    if insn.ops[0].addr != insn.ea + insn.size + 1:
        return False, None

    return True, 4


SEG_X = 0b001
SEG_W = 0b010
SEG_R = 0b100


OBFUSCATIONS = [
    is_jump_plus_one,
    is_jmp_ret,
    is_stc_jb,
    is_clc_jnb,
]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    for segstart in idautils.Segments():
        seg = ida_segment.getseg(segstart)
        if not (seg.perm & SEG_X):
            continue

        seg_name = ida_segment.get_segm_name(seg)

        for ea in range(seg.start_ea, seg.end_ea):
            for obfuscation in OBFUSCATIONS:
                is_ob, size = obfuscation(ea)
                if not is_ob:
                    continue

                logger.info(
                    "%s: 0x%x: found obfuscation(%s)",
                    seg_name,
                    ea,
                    obfuscation.__name__,
                )
                nop_region(ea, size)

    print("ok")
