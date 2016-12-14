# yara_fn

IDAPython script that generates a YARA rule to match against the
basic blocks of the current function. It masks out relocation bytes
and ignores jump instructions (given that we're already trying to
match compiler-specific bytes, this is of arguable benefit).

If python-yara is installed, the IDAPython script also validates that
the generated rule matches at least one segment in the current file.

## installation

none

## usage

invoke the script via `File->Script file...`. review the text written to the output pane.
