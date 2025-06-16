# IDA Pro Plugin Manager

The IDA Pro Plugin Manager is a tool to help you discover, install, and manage IDA Pro plugins distributed via a central index. It should be *very easy* for you extend the capabilities of IDA Pro with plugins, whether they are written in IDAPython or compiled languages like C/C++.

Quickstart:
```bash
# one time installation
$ pip install idapro-plugin-manager
$ ippm register

# find some plugins
$ ippm list
$ ippm show williballenthin-hint-calls-ida-plugin
$ ippm install williballenthin-hint-calls-ida-plugin
$ ippm update williballenthin-hint-calls-ida-plugin
$ ippm update-all
$ ippm remove williballenthin-hint-calls-ida-plugin
```

We'll also work to provide an IDA-native GUI for list/install/upgrade/removing plugins in the future.

Available plugins:

| Name                                      | Summary                                      |
|--------------------------------------------|----------------------------------------------|
| [3p-HRDevHelper-ida-plugin](https://github.com/patois/HRDevHelper)  | A helpful tool for debugging and developing your own Hexrays plugins and scripts by [Dennis Elser](https://github.com/patois/HRDevHelper) |
| [3p-HexInlay-ida-plugin](https://github.com/milankovo/hexinlay) | Inlay hints for hex-rays decompiler - shows function argument names in decompiled code by [Milan Bohacek](https://github.com/milankovo/hexinlay) |
| [3p-HexRaysPyTools-ida-plugin](https://github.com/igogo-x86/HexRaysPyTools) | IDA Pro plugin which improves work with HexRays decompiler and helps in process of reconstruction structures and classes by [igogo-x86](https://github.com/igogo-x86/HexRaysPyTools) |
| [3p-hexlight-ida-plugin](https://github.com/stevemk14ebr/RETools) | Highlighting plugin for Hex-Rays Decompiler - highlights matching braces and allows navigation with 'B' key by [Milan Bohacek](https://github.com/stevemk14ebr/RETools) |
| [3p-hex-highlighter-ida-plugin](https://github.com/vmallet/ida-hex-highlighter) | Highlight code blocks in IDA Pro's Hex-Rays decompiler output to make it easier to follow nested blocks by [Vincent Mallet](https://github.com/vmallet/ida-hex-highlighter) |
| [3p-IDAFuzzy-ida-plugin](https://github.com/Ga-ryo/IDAFuzzy) | Fuzzy searching tool for IDA Pro by [Ga-ryo](https://github.com/Ga-ryo/IDAFuzzy) |
| [3p-LazyIDA-ida-plugin](https://github.com/L4ys/LazyIDA) | Make your IDA Lazy! A collection of useful utilities for IDA Pro analysis by [Lays](https://github.com/L4ys/LazyIDA) |
| [3p-easy-nop-ida-plugin](https://github.com/stevemk14ebr/RETools) | Easy nopping tool for your nopping needs by [stevemk14ebr](https://github.com/stevemk14ebr/RETools) |
| [3p-string-from-selection-ida-plugin](https://github.com/stevemk14ebr/RETools) | Define a string from selection, useful for non-null terminated strings by [stevemk14ebr](https://github.com/stevemk14ebr/RETools) |
| [3p-SwiftStringInspector-ida-plugin](https://github.com/keowu/swiftstringinspector) | A simple plugin for working with Swift Strings, optimized Swift Strings, and Swift Arrays during the reverse engineering of iOS binaries by [Keowu](https://github.com/keowu/swiftstringinspector) |
| [3p-d810-ida-plugin](https://github.com/joydo/d810) | IDA Pro plugin to deobfuscate code at decompilation time by modifying IDA Pro microcode by [EShard Team](https://github.com/joydo/d810) |
| [3p-deREFerencing-ida-plugin](https://github.com/danigargu/deREferencing) | IDA Pro plugin that implements more user-friendly register and stack views by [Daniel Garcia](https://github.com/danigargu/deREferencing) |
| [3p-xrefer-ida-plugin](https://github.com/mandiant/xrefer) | FLARE Team's Binary Navigator. XRefer is a Python-based plugin for IDA Pro that provides a custom navigation interface, analyzes execution paths, clusters functions, and highlights downstream behaviors. It can incorporate external data and integrates with LLMs for code descriptions. |
| [3p-terminal-ida-plugin](https://github.com/HexRaysSA/ida-terminal-plugin) | A lightweight terminal integration for IDA Pro that lets you open a fully functional terminal within the IDA GUI by [Hex-Rays SA](https://github.com/HexRaysSA/ida-terminal-plugin) |
| [williballenthin-colorize-calls-ida-plugin](https://github.com/williballenthin/idawilli/tree/master/plugins/colorize_calls)  | IDA Pro plugin to colorize call instructions and add a prefix |
| [williballenthin-hint-calls-ida-plugin](https://github.com/williballenthin/idawilli/tree/master/plugins/hint_calls)      | IDA Pro plugin to display popup function hints for the referenced calls and strings |
| [williballenthin-navband-visited-ida-plugin](https://github.com/williballenthin/idawilli/tree/master/plugins/navband_visited) | IDA Pro plugin to highlight visited addresses in the navigation band. |
| [williballenthin-tag-func-ida-plugin](https://github.com/williballenthin/idawilli/tree/master/plugins/tag_func)        | IDA Pro plugin for tagging functions into folders |
| [williballenthin-basic-ida-plugin](https://www.github.com/williballenthin/idawilli/tree/master/plugins/plugin-manager/examples/basic-ida-plugin/)               | Example IDA Plugin                           |
| [williballenthin-multifile-ida-plugin](https://www.github.com/williballenthin/idawilli/tree/master/plugins/plugin-manager/examples/multifile-ida-plugin/)           | Example IDA Plugin with multiple files        |

Each of these you can install via: `ippm install ...`.

As a user of IDA Pro, learn more:
  - [Installation Instructions](./doc/as-a-user.md#installation)
  - [Command-Line Tool (`ippm`)](./doc/as-a-user.md#command-line-tool-ippm)

As a plugin author, learn more about how to package your IDA Pro plugins for distribution:
  - [Packaging Plugins](./doc/as-a-plugin-author.md#packaging-plugins)
  - [Entry Points](./doc/as-a-plugin-author.md#entry-points)

