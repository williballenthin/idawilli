# lumina_metadata

IDAPython script that queries the configured Lumina servers for each function and writes a summary of the returned record into the function comment.
The script does not apply the metadata to the database.
For each server, the summary shows the Lumina name (and the local name when they differ), the match frequency, the metadata score, the record size, the prototype, the function comments, the frame member names, and counts of instruction comments, extra comments, operand representations, and user stack points.
It then lists each version of the record, newest first, with the date and the name.
The comment shows the 10 newest versions, and the JSON output has all versions with their decoded metadata.

```
.text:004038F0 ; Lumina primary: _memcpy (local name: _memcpy_0)
.text:004038F0 ;   frequency 63,008, score 2910, size 0x335
.text:004038F0 ;   type: void *__cdecl _memcpy(void *Dst, const void *Src, size_t Size)
.text:004038F0 ;   frame: Dst, Src, Size
.text:004038F0 ;   36 instruction comments, 1 extra comment, 58 operand representations
.text:004038F0 ;   history: 2 versions, newest first
.text:004038F0 ;     2018-12-01 02:46 _memcpy
.text:004038F0 ;     2018-12-01 02:46 _memmove
```

The block starts at the first line that matches `Lumina primary: ` or `Lumina secondary: `.
When you run the script again, it replaces this block and keeps the text above it.

IDAPython does not wrap the history request, which IDA uses for the "Lumina > Metadata History" view.
The script calls `ida_lumina_client_t::get_func_histories` through the C++ vtable with ctypes and reads the result structures from memory.
The vtable slot and the structure layouts depend on the IDA build, so the script supports only IDA 9.5 on macOS and Linux and stops with an error on other versions.

## usage

In IDA, run the script with `File > Script file...`.

Without the GUI, use idalib. This opens or creates the database next to the input and saves it on exit.
Use `--json` to also write the records to stdout:

```
uv run scripts/lumina_metadata/lumina_metadata.py --json path/to/input.exe > records.json
```

If Lumina is not enabled in the IDA settings, set the server with environment variables:

```
LUMINA_PRIMARY=lumina.hex-rays.com:443 LUMINA_PRIMARY_TLS=YES uv run scripts/lumina_metadata/lumina_metadata.py path/to/input.exe
```
