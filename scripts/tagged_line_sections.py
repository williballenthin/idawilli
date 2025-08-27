from ida_lines import COLSTR, tag_addr, tag_remove
from ida_kernwin import tagged_line_sections_t, parse_tagged_line_sections, tagged_line_section_t

# Consider that we've generated a tagged line with an embedded address
#  (or that we have an existing line, whatever).
# And the user clicks on the word following the tag, so they can navigate to it.
# (This already works in the disassembly view, etc., but for simplecustviewer_t,
#  the plugin author has to implement the parsing themself.)
# Ok, so we use `parse_tagged_line_sections` to find the address tag, right?
#
# Not so fast, because `tagged_line_section_t` doesn't expose the byte offset of the section!


#        want to recover this number v
#                                    v          x  <--- from this click location
line = "AAAA" + tag_addr(0x401000) + "ZZZZ"
# ascii: AAAA(0000000000401000ZZZZ
# hex:   414141410128303030303030303030303430313030305a5a5a5a
# 
# ascii:  A  A  A  A ON ADDR  0  0  0  0  0  0  0  0  0  0  4  0  1  0  0  0  Z  Z  Z  Z
# hex:   41 41 41 41 01 28   30 30 30 30 30 30 30 30 30 30 34 30 31 30 30 30 5A 5A 5A 5A
# index  00 01 02 03 04 05   06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19
#                                                                            ^     x <---click location
#                                                                            |      
#                                                                            start/end of ADDR section

#
# Let me show you the diagram above is correct:
#
assert len(line) == 0x1A
assert line[0] == "A"
assert line[4] == "\x01"
assert line[5] == "\x28"

#
# Ok, so we parse the sections:
# 
tls = tagged_line_sections_t()
if not parse_tagged_line_sections(tls, line):
    print("error")

#
# But if we ask at any index, there are no associated sections
# because ADDR has zero length:
#
for i in range(len(line)):
    assert tls.nearest_at(i, 0) == None  # 0 = any tag

#
# Ok, so we can ask about the nearest_before section,
# which requires a containing section, so lets create that by hand:
#
whole = tagged_line_section_t()
# start and length are text offsets, not byte offsets
# so they're a little painful to deal with (imagine nested sections).
# but this seems to work anyways.
whole.start = 0
whole.length = len(tag_remove(line))

#
# Here is our mouse click, at character index 0x18:
# 
x = 0x18
z = tls.nearest_before(whole, x, 0)
# print(z)
# {start=4, length=0 (end=4), byte_offsets={text_start=22,  text_end=22},  tag=40}
# {start=4, length=0 (end=4), byte_offsets={text_start=16h, text_end=16h}, tag=40}
 
# Ok, so what do we have access to?
# print(dir(z))
# ['contains', 'is_closed', 'is_open', 'length', 'start', 'substr', 'tag', 'valid', 'valid_in']

#
# But all these things are text index units,
#  which means we can use them with the results of tag_remove,
#  but not with the raw line data.
# So they're not suitable for parsing the ADDR:
# 
assert z.start == 0x4  # text index
assert z.length == 0x0  # text length
assert z.tag == 0x28  # COLOR_ADDR
assert z.substr(line) == ""  # text substring, not byte buffer contents

# What we really need are the byte offsets, so that we can do:
# 
# assert line[0x6:0x16] == 0000000000401000
# assert line[0x16 - COLOR_ADDR_LENGTH:0x16] == 0000000000401000
# assert line[z.byte_offsets.text_start - COLOR_ADDR_LENGTH:z.byte_offsets.text_start] == 0000000000401000
#
# Which lets us reconstruct the address:
# 
# assert int(line[0x6:0x16], 0x10) == 0x401000

# I propose we should add `z.byte_start` and `z.byte_end`.


# Addendum:
# There *may* also be an additional concern, that these are byte offsets,
#  but `line` is a str and accepts character indices.
# Therefore I suspect things can get confused when
#  dealing with a line that contains a valid multi-byte string character sequence.


import idaapi
for t in tls:
    print(t)
    if t.tag==idaapi.COLOR_ADDR:
        addrstr = line[t.start+2:t.start+2+idaapi.COLOR_ADDR_SIZE]
        print (addrstr, hex(int(addrstr, 16)))
