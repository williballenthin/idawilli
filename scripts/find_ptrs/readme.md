# ida_find_ptrs.py

IDAPython script that scans through the .text section for values that could be pointers (32-bit). 
It marks these elements as such. 
This is useful when IDA Pro's auto-analysis leaves lots of unstructured data lying around.
