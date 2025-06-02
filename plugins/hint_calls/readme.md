# Hint Calls Plugin

IDA Pro plugin to display popup function hints for the referenced calls and strings.

## Features

- Shows function calls and string references as tooltips when hovering over function addresses
- Displays the number of calls, strings, and cross-references
- Lists all function calls and string literals used within a function
- Works in IDA Pro's disassembly view

## Installation

Assuming you have the [IDA Pro Plugin Manager](/plugins/plugin-manager/), install via pip:

```bash
pip install hint-calls-ida-plugin
```

Make sure to use the pip from your IDAPython installation.
