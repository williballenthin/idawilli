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
| [3p-HRDevHelper-ida-plugin](https://github.com/patois/HRDevHelper)  | A helpful tool for debugging and developing your own Hexrays plugins and scripts |
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

