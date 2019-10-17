'''
IDAPython script that colors instructions.

Author: Willi Ballenthin <william.ballenthin@fireeye.com>
Licence: Apache 2.0
'''
import logging
from collections import namedtuple

import ida_settings

import idc
import idaapi
import idautils
import ida_ua
import ida_bytes
import ida_segment


logger = logging.getLogger(__name__)
settings = ida_settings.IDASettings('idawilli.color')

CALL_COLOR = settings.get('colors.instructions.call', 0xD7C2C0)      # blueish
ENCRYPT_COLOR = settings.get('colors.behaviors.encrypt', 0xC0C2D7)   # redish
ANTIANALYSIS_COLOR = settings.get(
    'colors.behaviors.anti-analysis', 0xC0C2D7)  # redish


Segment = namedtuple('Segment', ['start', 'end', 'name'])


def enum_segments():
    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        yield Segment(seg.start_ea, seg.end_ea, seg.name)


def enum_heads():
    for segment in enum_segments():
        for head in idautils.Heads(segment.start, segment.end):
            yield head


def color_head(ea):
    flags = ida_bytes.get_flags(ea)
    if not ida_bytes.is_code(flags):
        return

    mnem = ida_ua.print_insn_mnem(ea)
    if mnem == 'call':
        logger.debug('call: 0x%x', ea)
        idc.set_color(ea, idc.CIC_ITEM, CALL_COLOR)
    elif mnem == 'xor':
        if idc.get_operand_value(ea, 0) != idc.get_operand_value(ea, 1):
            logger.debug('non-zero xor: 0x%x', ea)
            idc.set_color(ea, idc.CIC_ITEM, ENCRYPT_COLOR)
    elif mnem in ('sdit', 'sgdt', 'sldt', 'smsw', 'str', 'in', 'cpuid'):
        logger.debug('anti-vm: 0x%x', ea)
        idc.set_color(ea, idc.CIC_ITEM, ANTIANALYSIS_COLOR)
    elif mnem == 'in':
        if idc.get_operand_value(ea, 0) in ("3", "2D"):
            logger.debug('anti-debug: 0x%x', ea)
            idc.set_color(ea, idc.CIC_ITEM, ANTIANALYSIS_COLOR)
    elif mnem in ('rdtsc', 'icebp'):
        logger.debug('anti-debug: 0x%x', ea)
        idc.set_color(ea, idc.CIC_ITEM, ANTIANALYSIS_COLOR)


def main(argv=None):
    if argv is None:
        argv = sys.argv[:]

    for head in enum_heads():
        color_head(head)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
