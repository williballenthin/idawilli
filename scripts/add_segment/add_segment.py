'''
IDAPython plugin that adds the contents of a file as a new segment in an existing idb.
Prompts the user for:
  - file path
  - segment name
  - segment starting offset
  
Useful for reversing engineering packed software and shellcode.

Author: Willi Ballenthin <william.ballenthin@fireeye.com>
Licence: Apache 2.0
'''
import logging
from collections import namedtuple

import idc
import idaapi
import idautils


logger = logging.getLogger(__name__)


class BadInputError(Exception):
    pass


Segment = namedtuple('SegmentBuffer', ['path', 'name', 'addr'])


def prompt_for_segment():
    ''' :returns: a Segment instance, or raises BadInputError '''
    class MyForm(idaapi.Form):
        def __init__(self):
            idaapi.Form.__init__(self, """STARTITEM 0
add segment by buffer

<##buffer path:{path}>
<##segment name:{name}>
<##segment start address:{addr}>
""",
{
    'path': idaapi.Form.FileInput(open=True),
    'name': idaapi.Form.StringInput(),
    'addr': idaapi.Form.NumericInput(tp=Form.FT_ADDR),
})

        def OnFormChange(self, fid):
            return 1

    f = MyForm()
    f.Compile()
    f.path.value = ""
    f.name.value = ""
    f.addr.value = 0x0
    ok = f.Execute()
    if ok != 1:
        raise BadInputError('user cancelled')

    path = f.path.value
    if path == "" or path is None:
        raise BadInputError('bad path provided')

    if not os.path.exists(path):
        raise BadInputError('file doesn\'t exist')

    name = f.name.value
    if name == "" or name is None:
        raise BadInputError('bad name provided')

    addr = f.addr.value
    f.Free()
    return Segment(path, name, addr)


def main(argv=None):
    if argv is None:
        argv = sys.argv[:]

    try:
        seg = prompt_for_segment()
    except BadInputError:
        logger.error('bad input, exiting...')
        return -1

    with open(seg.path, 'rb') as f:
        buf = f.read()

    seglen = len(buf)
    if seglen % 0x1000 != 0:
        seglen = seglen + (0x1000 - (seglen % 0x1000))

    if not idc.AddSeg(seg.addr, seg.addr + seglen, 0, 1, 0, idaapi.scPub):
        logger.error('failed to add segment: 0x%x', seg.addr)
        return -1

    if not idc.RenameSeg(seg.addr, seg.name):
        logger.warning('failed to rename segment: %s', seg.name)

    if not idc.SetSegClass(seg.addr, 'CODE'):
        logger.warning('failed to set segment class CODE: %s', seg.name)

    if not idc.SegAlign(seg.addr, idc.saRelPara):
        logger.warning('failed to align segment: %s', seg.name)

    idaapi.patch_many_bytes(seg.addr, buf)
    

class AddSegmentPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Add a segment to an IDA .idb from a file."

    help = "Add a segment to an IDA .idb from a file."
    wanted_name = "AddSegment"
    wanted_hotkey = "Alt-F8"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        main()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return AddSegmentPlugin()


#if __name__ == '__main__':
#    logging.basicConfig(level=logging.DEBUG)
#    main()