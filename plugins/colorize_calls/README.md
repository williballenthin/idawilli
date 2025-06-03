# Colorize Calls IDA Pro Plugin

IDA Pro plugin to colorize call instructions and add a prefix in the disassembly listing.
This doesn't touch the database, it dynamically updates the view as you browse, so you don't have to worry about bothering your colleagues if you share the .idb.

## Features

-   **Background Color:** Changes the background color of `call` instructions in the disassembly view.
-   **Instruction Prefix:** Adds a `>>>` prefix to `call` instructions.

## Installation

Assuming you have the [IDA Pro Plugin Manager](https://github.com/williballenthin/idawilli/tree/master/plugins/plugin-manager/), install via pip:

```bash
pip install williballenthin-colorize-calls-ida-plugin
```

Make sure to use the pip from your IDAPython installation.
