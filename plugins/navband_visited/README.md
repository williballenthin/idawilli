# Navband Visited IDA Pro Plugin

IDA Pro plugin that tracks and records all disassembly addresses you visit during your analysis, highlighting these visited addresses in IDA's navigation band.

## Features

-   Automatically records addresses as you navigate through them in the disassembly view.
-   Colors the corresponding locations in the navigation band (navband) black to indicate they have been visited.
-   Persists as long as IDA is open, helping you keep track of explored code regions.

## Installation

Assuming you have the [IDA Pro Plugin Manager](https://github.com/williballenthin/idawilli/tree/master/plugins/plugin-manager) (or a compatible setup that recognizes `idapro.plugins` entry points), install via pip:

```bash
pip install williballenthin-navband-visited-ida-plugin
```

Make sure to use the `pip` associated with your IDAPython environment.

## Publishing

This plugin is available on PyPI:
[https://pypi.org/project/williballenthin-navband-visited-ida-plugin/](https://pypi.org/project/williballenthin-navband-visited-ida-plugin/)

The GitHub Actions workflow for publishing is defined in [`.github/workflows/publish-navband-visited-ida-plugin.yml`](../../.github/workflows/publish-navband-visited-ida-plugin.yml).
