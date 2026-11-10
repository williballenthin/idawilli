# Hint Lumina IDA Pro Plugin

IDA Pro plugin that shows the Lumina record of a function as a hint.
In the disassembly view, hover over the function name in the function header, such as the prototype comment or the `proc near` line.
The plugin then queries the configured Lumina servers for that function and shows the record without applying it.

```
Lumina primary: _memcpy (local name: _memcpy_0)
  frequency 63,008, score 2910, size 0x335
  type: void *__cdecl _memcpy(void *Dst, const void *Src, size_t Size)
  frame: Dst, Src, Size
  36 instruction comments, 1 extra comment, 58 operand representations
  history: 2 versions, newest first
    2018-12-01 02:46 _memcpy
    2018-12-01 02:46 _memmove
```

The hint has the same content as the function comments that `scripts/lumina_metadata` writes.
The first line names the server and the Lumina name, and adds the local name when the two differ.
`frequency` is a counter on the server that increases each time a client pull matches the record.
The plugin sets `PULL_MD_SEEN_FILE`, so its requests do not change the counter.
`score` is the sum of the points that IDA gives to each part of the metadata, for example 500 for a name, 500 for a type, and 30 for each instruction comment.
It does not tell how well the record matches the local function.
`size` is the size in bytes of the function that the record came from.
The history lists the 10 newest versions with the date and the name.

The first hover on a function sends one metadata request and one history request to each server, which can stop the UI for about a second.
The plugin keeps the result, or the error, until the database closes.

IDAPython does not wrap the history request, so the plugin calls `ida_lumina_client_t::get_func_histories` through the C++ vtable with ctypes.
The vtable slot and the structure layouts depend on the IDA build, so the plugin supports only IDA 9.5 on macOS and Linux.

## Installation

Download or symlink this directory into `%IDAUSR%/plugins/hint-lumina`.
Enable Lumina in the IDA options, or start IDA with the server in environment variables:

```
LUMINA_PRIMARY=lumina.hex-rays.com:443 LUMINA_PRIMARY_TLS=YES ida
```
