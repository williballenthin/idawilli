"""Small read helpers over the IDA database used by the integration tests."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Segment:
    name: str
    start: int
    end: int
    bitness: int


def get_segments() -> list[Segment]:
    import ida_segment

    out = []
    for i in range(ida_segment.get_segm_qty()):
        s = ida_segment.getnseg(i)
        out.append(
            Segment(ida_segment.get_segm_name(s), s.start_ea, s.end_ea, s.bitness)
        )
    return out


def get_bytes(ea: int, size: int) -> bytes:
    import ida_bytes

    return ida_bytes.get_bytes(ea, size)


def get_root_filename() -> str:
    import ida_nalt

    return ida_nalt.get_root_filename()


def get_filetype() -> int:
    import ida_ida

    return ida_ida.inf_get_filetype()
