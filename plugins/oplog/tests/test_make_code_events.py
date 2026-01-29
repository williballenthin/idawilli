import textwrap
from pathlib import Path

from conftest import run_ida_script
from oplog_events import (
    EventList,
    InsnModel,
    OpModel,
    make_code_event,
)


def test_make_code(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that creating code triggers make_code event."""
    events_path = work_dir / "events.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f'''
            import idc
            import ida_bytes
            import ida_ua

            test_ea = 0x401000

            ida_bytes.del_items(test_ea, ida_bytes.DELIT_SIMPLE)

            size = ida_ua.create_insn(test_ea)

            idc.eval_idc('oplog_export("{events_path}")')
        '''),
    )

    event_list = EventList.model_validate_json(events_path.read_text())
    make_code_events = [e for e in event_list.root if isinstance(e, make_code_event)]

    matching = [e for e in make_code_events if e.insn.ea == 0x401000]
    assert len(matching) >= 1, "No make_code event found for address 0x401000"

    actual = matching[-1]

    expected = make_code_event(
        event_name="make_code",
        timestamp=actual.timestamp,
        insn=InsnModel(
            cs=0,
            ip=0x401000,
            ea=0x401000,
            itype=122,
            size=4,
            auxpref=7240,
            segpref=0,
            insnpref=0,
            flags=2,
            ops=[
                OpModel(n=0, type=1, offb=0, offo=0, flags=8, dtype=2, reg=2, phrase=2, value=0, addr=0, specval=0, specflag1=0, specflag2=0, specflag3=0, specflag4=0),
                OpModel(n=1, type=4, offb=3, offo=0, flags=8, dtype=2, reg=4, phrase=4, value=0, addr=8, specval=2031616, specflag1=1, specflag2=36, specflag3=0, specflag4=0),
                OpModel(n=2, type=0, offb=0, offo=0, flags=8, dtype=0, reg=0, phrase=0, value=0, addr=0, specval=0, specflag1=0, specflag2=0, specflag3=0, specflag4=0),
                OpModel(n=3, type=0, offb=0, offo=0, flags=8, dtype=0, reg=0, phrase=0, value=0, addr=0, specval=0, specflag1=0, specflag2=0, specflag3=0, specflag4=0),
                OpModel(n=4, type=0, offb=0, offo=0, flags=8, dtype=0, reg=0, phrase=0, value=0, addr=0, specval=0, specflag1=0, specflag2=0, specflag3=0, specflag4=0),
                OpModel(n=5, type=0, offb=0, offo=0, flags=8, dtype=0, reg=0, phrase=0, value=0, addr=0, specval=0, specflag1=0, specflag2=0, specflag3=0, specflag4=0),
                OpModel(n=6, type=0, offb=0, offo=0, flags=8, dtype=0, reg=0, phrase=0, value=0, addr=0, specval=0, specflag1=0, specflag2=0, specflag3=0, specflag4=0),
                OpModel(n=7, type=0, offb=0, offo=0, flags=8, dtype=0, reg=0, phrase=0, value=0, addr=0, specval=0, specflag1=0, specflag2=0, specflag3=0, specflag4=0),
            ],
        ),
    )
    assert actual == expected
