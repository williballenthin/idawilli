# Colorize Calls IDA Pro Plugin

IDA Pro plugin to colorize call instructions and add a prefix in the disassembly listing.
This doesn't touch the database, it dynamically updates the view as you browse, so you don't have to worry about bothering your colleagues if you share the .idb.

## Features

-   **Background Color:** Changes the background color of `call` instructions in the disassembly view.
-   **Instruction Prefix:** Adds a `>>>` prefix to `call` instructions.

## Installation

Download or symlink this directory into `%IDAUSR%/plugins/colorize_calls`.
