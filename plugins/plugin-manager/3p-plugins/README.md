This directory contains IDA Pro plugins that I've migrated to use the IDA Pro Plugin Manager format.
The ultimate goal is to upstream this work;
 in the interim, this provides a way to expose popular plugins on the platform.

## Migration strategy:
Use a script to import external sources and apply patches.

  - we'll try to avoid commiting the external sources directly into this repo
  - by using a script, we can create patches like "move this from from here to there", rather than git-style delete+add, which I think will compose better with rebasing external sources during updates. The "move" patches should be more common than line-oriented patches.
  - originally I used Copybara, but it didn't support copy multiple source repositories to a single destination directory.

## Migrating
To develop a migration with the help of an AI agent, you can use a prompt like:

> using the notes in plugins/plugin-manager/3p-plugins/AGENT.md, develop a migration for @https://github.com/keowu/swiftstringinspector

## Building

To import, build, and test the migrated plugins, use the Justfile:
  1. `just import`
  2. `just build`
  3. `just test`

Manual steps:
  1. `python migrate_plugins.py`
  2. `cd third_party/<plugin> && python -m build --wheel`
  3. `python ../scripts/test_plugin.py third_party/<plugin>/dist/*.whl`
