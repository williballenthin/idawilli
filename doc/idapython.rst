segments
--------

enumerate segments::

    Segment = namedtuple('Segment', ['start', 'end', 'name'])
    def enum_segments():
        for segstart in idautils.Segments():
            segend = idc.SegEnd(segstart)
            segname = idc.SegName(segstart)             
            yield Segment(segstart, segend, segname)

heads
-----

a `head` is a defined item in an idb.
for example, a defined byte, dword, instruction, etc. 

enumerate heads::

    for segment in enum_segments():
        for head in idautils.Heads(segment.start, segment.end):
            print(hex(head))

note that just because there is a byte value at an address does not mean there is a head there.
use ``idc.isHead(idc.getFlags(address))`` to test head-ness. for example, consider the following::

    0000 seg000		segment	byte public 'CODE' use32
    0000    assume cs:seg000
    0000    assume es:nothing, ss:nothing, ds:nothing, fs:nothing, gs:nothing
    0000    db    ?	;  NOT HEAD
    0001    db    ?	;  NOT HEAD
    0002    db    ?	;  NOT HEAD
    0003    db  90h	;  NOT HEAD
    0004    dw 9090h;  HEAD
    0006    db 90h  ;  HEAD
    0007 ; ---------------------------------------------------------------------------
    0007    nop     ;  HEAD
    0007 ; ---------------------------------------------------------------------------

although there is a byte at address 0003, it has not been defined like the byte at 0006.

names and comments can be set an any address, not just heads. 
so in the above example, the byte at address 0003 may have a name and comment, but not be considered a head.
however, when fetching comments you need to be a bit careful: heads may span multiple bytes, and fetching comments from any address within the head fetches the head's comments.
given the above example, the following is true::

    idc.MakeComm(0x4, 'a comment')
    assert idc.Comm(0x4) == 'a comment'
    assert idc.Comm(0x5) == 'a comment'


text encoding
-------------

on different systems, IDA may use different codepages.
all IDAPython APIs accept and return the python type ``str`` for strings, and they do not accept the ``unicode`` type.

for compatibility across users, you should explicitly encode and decode to/from ASCII::

    idc.MakeName(0x0, u'foobar'.encode('ascii', errors='replace'))
    idc.Name(0x0).decode('ascii', errors='replace')


commenting
----------

create local comment::

    if not idc.MakeComm(va, ctext):
        logger.warning('failed to create local comment: 0x%x', va)

delete local comment::

    if not idc.MakeComm(va, ''):
        logger.warning('failed to delete local comment: 0x%x', va)

create repeatable comment::

    if not idc.MakeRptCmt(va, ctext):
        logger.warning('failed to create repeatable comment: 0x%x', va)
        
delete repeatable comment::

    if not idc.MakeRptCmt(va, ''):
        logger.warning('failed to delete repeatable comment: 0x%x', va)
        
create anterior comment::

    for i, line in enumerate(ctext.split('\n')):
        if not idc.ExtLinA(va, i, line):
            logger.warning('failed to create anterior line comment: 0x%x %d', va, i)
            
delete anterior comment::

    # deleting line 0 deletes all the rest, too
    if not idc.DelExtLnA(va, 0):
        logger.warning('failed to delete anterior comment: 0x%x', va)

create posterior comment::

    for i, line in enumerate(ctext.split('\n')):
        if not idc.ExtLinB(va, i, line):
            logger.warning('failed to create posterior line comment: 0x%x %d', va, i)

delete posterior comment::

    if not idc.DelExtLnB(va, 0):
        logger.warning('failed to delete anterior comment: 0x%x', va)
        
create function comment::

    if not idc.SetFunctionCmt(va, ctext, False):
        logger.warning('failed to create function local comment: 0x%x', va)

delete function comment::

    if not idc.SetFunctionCmt(va, '', False):
        logger.warning('failed to delete function local comment: 0x%x', va)
        
create repeatable function comment::

    if not idc.SetFunctionCmt(va, ctext, True):
        logger.warning('failed to create function repeatable comment: 0x%x', va)
        
delete repeatable function comment::

    if not idc.SetFunctionCmt(va, '', True):
        logger.warning('failed to delete function repeatablecomment: 0x%x', va)


types
--------------------------

inspect function prototype::

    tup = idaapi.get_named_type(None, 'CreateServiceA', idaapi.NTF_SYMM)
    if tup is not None:
        code, type_str, fields_str, cmt, field_cmts, sclass, value  = tup
        t1 = idaapi.tinfo_t()
        t1.deserialize(None, type_str, fields_str, cmt)
        print('Number of args: %d' % t1.get_nargs())
        print('Type of arg 0: %s' %t1.get_nth_arg(0)._print())
        print('Size of arg 0: %d' % t1.get_nth_arg(0).get_size())







