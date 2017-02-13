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


logger = logging.getLogger(__name__)
settings = ida_settings.IDASettings('idawilli.color')

CALL_COLOR = settings.get('colors.instructions.call', 0xD7C2C0)      # blueish
ENCRYPT_COLOR = settings.get('colors.behaviors.encrypt', 0xC0C2D7)   # redish
ANTIANALYSIS_COLOR = settings.get('colors.behaviors.anti-analysis', 0xC0C2D7)  # redish


Segment = namedtuple('Segment', ['start', 'end', 'name'])
def enum_segments():
    for segstart in idautils.Segments():
        segend = idc.SegEnd(segstart)
        segname = idc.SegName(segstart)
        yield Segment(segstart, segend, segname)


def enum_heads():
    for segment in enum_segments():
        for head in idautils.Heads(segment.start, segment.end):
            yield head


def color_head(ea):
    flags = idc.GetFlags(ea)
    if not idc.isCode(flags):
        return

    mnem = idc.GetMnem(ea)
    if mnem == 'call':
        logger.debug('call: 0x%x', ea)
        idc.SetColor(ea, idc.CIC_ITEM, CALL_COLOR)
    elif mnem == 'xor':
        if idc.GetOpnd(ea, 0) != idc.GetOpnd(ea, 1):
            logger.debug('non-zero xor: 0x%x', ea)
            idc.SetColor(ea, idc.CIC_ITEM, ENCRYPT_COLOR)
    elif mnem in ('sdit', 'sgdt', 'sldt', 'smsw', 'str', 'in', 'cpuid'):
        logger.debug('anti-vm: 0x%x', ea)
        idc.SetColor(ea, idc.CIC_ITEM, ANTIANALYSIS_COLOR)
    elif mnem == 'in':
        if idc.GetOpnd(ea, 0) in ("3", "2D"):
            logger.debug('anti-debug: 0x%x', ea)
            idc.SetColor(ea, idc.CIC_ITEM, ANTIANALYSIS_COLOR)
    elif mnem in ('rdtsc', 'icebp'):
        logger.debug('anti-debug: 0x%x', ea)
        idc.SetColor(ea, idc.CIC_ITEM, ANTIANALYSIS_COLOR)


def main(argv=None):
    if argv is None:
        argv = sys.argv[:]

    for head in enum_heads():
        color_head(head)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
