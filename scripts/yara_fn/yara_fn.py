'''
IDAPython script that generates a YARA rule to match against the
basic blocks of the current function. It masks out relocation bytes
and ignores jump instructions (given that we're already trying to
match compiler-specific bytes, this is of arguable benefit).

If python-yara is installed, the IDAPython script also validates that
the generated rule matches at least one segment in the current file.

author: Willi Ballenthin <william.ballenthin@fireeye.com>
'''

import logging
from collections import namedtuple

import idc
import idaapi
import idautils


logger = logging.getLogger(__name__)

BasicBlock = namedtuple('BasicBlock', ['va', 'size'])


# each rule must have at least this many non-masked bytes 
MIN_BB_BYTE_COUNT = 4


def get_basic_blocks(fva):
    '''
    return sequence of `BasicBlock` instances for given function.
    '''
    ret = []
    func = idaapi.get_func(fva)
    if func is None:
        return ret

    for bb in idaapi.FlowChart(func):
        ret.append(BasicBlock(va=bb.start_ea,
                              size=bb.end_ea - bb.start_ea))

    return ret


def get_function(va):
    '''
    return va for first instruction in function that contains given va.
    '''
    return idaapi.get_func(va).start_ea


Rule = namedtuple('Rule', ['name', 'bytes', 'masked_bytes'])


def is_jump(va):
    '''
    return True if the instruction at the given address appears to be a jump.
    '''
    return idc.print_insn_mnem(va).startswith('j')


def get_basic_block_rule(bb):
    '''
    create and format a YARA rule for a single basic block.
    mask relocation bytes into unknown bytes (like '??').
    do not include final instructions if they are jumps.
    '''
    # fetch the instruction start addresses
    insns = []
    va = bb.va
    while va < bb.va + bb.size:
        insns.append(va)
        va = idc.next_head(va)

    # drop the last instruction if its a jump
    if is_jump(insns[-1]):
        insns = insns[:-1]

    bytes = []
    # `masked_bytes` is the list of formatted bytes,
    #   not yet join'd for performance.
    masked_bytes = []
    for va in insns:
        size = idc.get_item_size(va)
        if idaapi.contains_fixups(va, size):
            # fetch the fixup locations within this one instruction.
            fixups = []
            fixupva = idaapi.get_next_fixup_ea(va)
            fixups.append(fixupva)
            # TODO: assume the fixup size is four bytes, probably bad.
            fixupva += 4

            while fixupva < va + size:
                fixupva = idaapi.get_next_fixup_ea(fixupva)
                fixups.append(fixupva)
                # TODO: assume the fixup size is four bytes, probably bad.
                fixupva += 4

            # assume each fixup is four bytes (TODO!),
            #  and compute the addresses of each component byte.
            fixup_byte_addrs = set([])
            for fixup in fixups:
                for i in range(fixup, fixup+4):
                    fixup_byte_addrs.add(i)
            
            # fetch and format each byte of the instruction,
            #  possibly masking it into an unknown byte if its a fixup.
            for i, byte in enumerate(idc.get_bytes(va, size)):
                byte_addr = i + va
                if byte_addr in fixup_byte_addrs:
                    bytes.append(byte)
                    masked_bytes.append('??')
                else:
                    bytes.append(byte)
                    masked_bytes.append('%02x' % int(byte.encode('hex'), 16))
        elif 'call' in idc.print_insn_mnem(va):
            for i, byte in enumerate(idc.get_bytes(va, size)):
                bytes.append(byte)
                masked_bytes.append('??')
        else:
            for byte in idc.get_bytes(va, size):
                bytes.append(byte)
                masked_bytes.append('%02x' % int(byte.encode('hex'), 16))

    return Rule('$0x%x' % (bb.va), bytes, masked_bytes)


def format_rules(fva, rules):
    '''
    given the address of a function, and the byte signatures for basic blocks in
     the function, format a complete YARA rule that matches all of the
     basic block signatures.
    '''
    name = idc.get_func_name(fva)

    # some characters aren't valid for YARA rule names
    safe_name = name
    BAD_CHARS = '@ /\\!@#$%^&*()[]{};:\'",./<>?'
    for c in BAD_CHARS:
        safe_name = safe_name.replace(c, '')

    md5 = idautils.GetInputFileMD5().hex()
    ret = []
    ret.append('rule a_{}_{}'.format(md5, safe_name))
    ret.append('  meta:')
    ret.append('    sample_md5 = "{}"'.format(md5))
    ret.append('    function_address = "0x{}"'.format(fva))
    ret.append('    function_name = "{}"'.format(name))
    ret.append('  strings:')
    for rule in rules:
        formatted_rule = ' '.join(rule.masked_bytes)
        ret.append('    {} = {{{}}}'.format(rule.name, formatted_rule))
    ret.append('  condition:')
    ret.append('    all of them')
    ret.append('}')
    return '\n'.join(ret)


def create_yara_rule_for_function(fva):
    '''
    given the address of a function, generate and format a complete YARA rule
     that matches the basic blocks.
    '''
    rules = []
    for bb in get_basic_blocks(fva):
        rule = get_basic_block_rule(bb)

        # ensure there at least MIN_BB_BYTE_COUNT
        #  non-masked bytes in the rule, or ignore it.
        # this will reduce the incidence of many very small matches.
        unmasked_count = len([b for b in rule.masked_bytes if b != '??'])
        if unmasked_count < MIN_BB_BYTE_COUNT:
            continue

        rules.append(rule)

    return format_rules(fva, rules)


def get_segment_buffer(segstart):
    '''
    fetch the bytes of the section that starts at the given address.
    if the entire section cannot be accessed, try smaller regions until it works.
    '''
    segend = idaapi.getseg(segstart).end_ea
    buf = None
    segsize = segend - segstart
    while buf is None:
        buf = idc.get_bytes(segstart, segsize)
        if buf is None:
            segsize -= 0x1000
    return buf


Segment = namedtuple('Segment', ['start', 'size', 'name', 'buf'])


def get_segments():
    '''
    fetch the segments in the current executable.
    '''
    for segstart in idautils.Segments():
         segend = idaapi.getseg(segstart).end_ea
         segsize = segend - segstart
         segname = str(idc.SegName(segstart)).rstrip('\x00')
         segbuf = get_segment_buffer(segstart)
         yield Segment(segstart, segend, segname, segbuf)


class TestDidntRunError(Exception):
    pass


def test_yara_rule(rule):
    '''
    try to match the given rule against each segment in the current exectuable.
    raise TestDidntRunError if its not possible to import the YARA library.
    return True if there's at least one match, False otherwise.
    '''
    try:
        import yara
    except ImportError:
        logger.warning("can't test rule: failed to import python-yara")
        raise TestDidntRunError('python-yara not available')

    r = yara.compile(source=rule)

    for segment in get_segments():
        matches = r.match(data=segment.buf)
        if len(matches) > 0:
            logger.info('generated rule matches section: {segment.name}')
            return True
    return False


def main():
    va = idc.get_screen_ea()
    fva = get_function(va)
    print(('-' * 80))
    rule = create_yara_rule_for_function(fva)
    print(rule)

    '''
    if test_yara_rule(rule):
        print('success: validated the generated rule')
    else:
        print('error: failed to validate generated rule')
    '''


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger().setLevel(logging.DEBUG)
    main()
