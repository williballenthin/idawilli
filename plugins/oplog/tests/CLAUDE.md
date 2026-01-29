# Oplog Test Development Guide

This guide explains how to write tests for oplog IDB events using the headless idalib test harness.

## Test Architecture

### Fixtures

- **`test_binary`** - Path to the test PE file (Practical Malware Analysis Lab 01-01.exe_)
- **`session_idauser`** - Session-scoped IDAUSR with oplog plugin installed. Reused across tests for speed.
- **`temp_idauser`** - Function-scoped IDAUSR. Use when you need a fresh environment per test.
- **`work_dir`** - Function-scoped temp directory for test artifacts

For most tests, use `test_binary` + `session_idauser` + `work_dir`. The IDB is automatically cleaned up after each test.

### Test Pattern

```python
import sys
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from conftest import run_ida_script
from oplog_events import (
    EventList,
    SegmentModel,
    segm_name_changed_event,
    # ... other event types
)


def test_some_event(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that <action> triggers <event_name> event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_segment

            # Perform the IDA operation that triggers the event
            # ...

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    # Parse JSON into typed Pydantic models
    event_list = EventList.model_validate_json(events_path.read_text())

    # Filter by event type using isinstance
    matching = [e for e in event_list.root if isinstance(e, some_event_type)]
    assert len(matching) >= 1

    actual = matching[-1]

    # Construct expected event with hardcoded snapshot values
    expected = some_event_type(
        event_name="some_event",
        timestamp=actual.timestamp,  # Always copy - dynamic
        # ... hardcode other fields as snapshot literals
    )
    assert actual == expected
```

## Snapshot Testing Philosophy

Tests should use **hardcoded snapshot literals** for expected values. This makes tests:
- **Self-documenting** - You can see exactly what events look like by reading the test
- **Regression-detecting** - Changes to event structure will cause test failures

## Always Copy (Truly Dynamic)
- `timestamp` - Changes every run

Everything else should be static snapshots

## **NEVER COPY DATA FROM ACTUAL TO EXPECTED**

Besides `timestamp`, **NEVER COPY DATA FROM ACTUAL TO EXPECTED**.
That doesn't test anything. If you need to understand data better, investigate it or ask for help.

## Running Tests

```bash
# Single test
python -m pytest tests/test_segm_events.py::test_segm_name_changed -v

# All segment tests
python -m pytest tests/test_segm_events.py -v

# Full suite
python -m pytest tests/ -v
```

## Debugging Tips

### Script errors silently?

Add print statements - they appear in stderr:

```python
script=textwrap.dedent(f'''
    import sys
    seg = ida_segment.get_first_seg()
    print(f"Got segment: {ida_segment.get_segm_name(seg)}", file=sys.stderr)
'''),
```

### Event not captured?

1. Check the event is in `oplog_events.py` and `oplog_hooks.py`
2. Verify the hook method is implemented
3. Check if the API triggers the IDB hook
4. Print `event_list.root` to see what was captured

### Serialization errors?

If you see "Unable to serialize unknown type", add a Pydantic model for the IDA type (see `SegmMoveInfoModel`).

## Known Quirks

1. **`from_ea` in `segm_moved_event`**: The hook uses `_from` but Pydantic doesn't serialize underscore-prefixed fields. Access via `event.from_ea` (aliased field).

2. **`adding_segm` timing**: Fires before segment name is set. Match by address, not name.

3. Several function-related hooks do NOT fire when calling IDA Python APIs directly. Perhaps these hooks only fire during IDA's internal auto-analysis phase:
   Tests for non-working hooks are marked with `@pytest.mark.xfail` to document the limitation while keeping the test infrastructure in place.

