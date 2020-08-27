'''
IDAPython script that saves the content of a segment to a file.
Prompts the user for:
  - segment name
  - file path

Useful for extracting data from memory dumps.

Author: Willi Ballenthin <william.ballenthin@fireeye.com>
Licence: Apache 2.0
'''
import logging
from collections import namedtuple

import idaapi
import ida_bytes
import ida_segment


logger = logging.getLogger(__name__)


class BadInputError(Exception):
    pass


Segment = namedtuple('SegmentBuffer', ['path', 'name'])


def prompt_for_segment():
    ''' :returns: a Segment instance, or raises BadInputError '''
    class MyForm(idaapi.Form):
        def __init__(self):
            idaapi.Form.__init__(self, """STARTITEM 0
add segment by buffer

<##segment name:{name}>
<##output path:{path}>
""",
                                 {
                                     'path': idaapi.Form.FileInput(save=True),
                                     'name': idaapi.Form.StringInput(),
                                 })

        def OnFormChange(self, fid):
            return 1

    f = MyForm()
    f.Compile()
    f.path.value = ""
    f.name.value = ""
    ok = f.Execute()
    if ok != 1:
        raise BadInputError('user cancelled')

    path = f.path.value
    if path == "" or path is None:
        raise BadInputError('bad path provided')

    name = f.name.value
    if name == "" or name is None:
        raise BadInputError('bad name provided')

    f.Free()
    return Segment(path, name)


def main(argv=None):
    if argv is None:
        argv = sys.argv[:]

    try:
        seg_spec = prompt_for_segment()
    except BadInputError:
        logger.error('bad input, exiting...')
        return -1

    seg = ida_segment.get_segm_by_name(seg_spec.name)
    if not seg:
        logger.error("bad segment, exiting...")

    buf = ida_bytes.get_bytes(seg.start_ea, seg.end_ea - seg.start_ea)
    with open(seg_spec.path, "wb") as f:
        f.write(buf)

    logger.info("wrote %x bytes", len(buf))


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
