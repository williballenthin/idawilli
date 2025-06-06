This directory contains IDA Pro plugins that I've migrated to use the IDA Pro Plugin Manager format.
The ultimate goal is to upstream this work;
 in the interim, this provides a way to expose popular plugins on the platform.

Migration strategy:
  - use Copybara to import external sources and apply patches
    - we'll try to avoid commiting the external sources directly into this repo
    - by using Copybara, we can create patches like "move this from from here to there",
      rather than git-style delete+add, which I think will compose better with rebasing external sources during updates.
      The "move" patches should be more common than line-oriented patches.


Steps:
  1. get Copybara from here: https://github.com/google/copybara/releases
  2. `java.jar copybara.jar copy.bara.sky --folder-dir=./third_party`
