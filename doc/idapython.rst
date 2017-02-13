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
