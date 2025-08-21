# oplog

oplog is an IDA Pro plugin that records operations during analysis in order to:

  1. show you a timeline of activity,
  2. export a trace, potentially to be used to train AI models on your reversing style,
  3. ... your idea here!

As you navigate and make changes to the IDB, it records a structure representation of the events (see [oplog_events.py](oplog_events.py)). The plugin persists the events into the IDB, renders a timeline for you (via View -> Open subviews -> oplog), and lets you export the trace in a JSON format (via oplog view -> Save to file...).

![demo](./img/Screen%20Recording%202025-08-20%20at%205.01.14%E2%80%AFPM.gif)

# installation

Download or symlink this directory into `%IDAUSR%/plugins/oplog`.
