# native-ida-plugin

## Build

Have the following installed:
  - cmake
  - zig
  - just
  - python, with package `build`

```
$ export IDASDK=~/.idapro/sdk/idasdk91/
$ just build
```

Then find the output file in `dist/native_ida_plugin-0.1.0-py3-none-any.whl`.
