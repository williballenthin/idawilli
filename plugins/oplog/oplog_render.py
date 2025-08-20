from datetime import datetime

import ida_funcs
import ida_lines
from ida_lines import COLSTR, tag_addr

from oplog_events import idb_event, renamed_event, frame_udm_renamed_event


def pretty_date(time: datetime):
    """
    Get a datetime object or a int() Epoch timestamp and return a
    pretty string like 'an hour ago', 'Yesterday', '3 months ago',
    'just now', etc

    via: https://stackoverflow.com/a/1551394
    """
    now = datetime.now()
    diff = now - time
    second_diff = diff.seconds
    day_diff = diff.days

    if day_diff < 0:
        return ""

    if day_diff == 0:
        if second_diff < 10:
            return "just now"
        if second_diff < 60:
            return str(second_diff) + " seconds ago"
        if second_diff < 120:
            return "a minute ago"
        if second_diff < 3600:
            return str(second_diff // 60) + " minutes ago"
        if second_diff < 7200:
            return "an hour ago"
        if second_diff < 86400:
            return str(second_diff // 3600) + " hours ago"
    if day_diff == 1:
        return "Yesterday"
    if day_diff < 7:
        return str(day_diff) + " days ago"
    if day_diff < 31:
        return str(day_diff // 7) + " weeks ago"
    if day_diff < 365:
        return str(day_diff // 30) + " months ago"
    return str(day_diff // 365) + " years ago"


def codname(name: str):
    """dummy code name"""
    return COLSTR(name, ida_lines.SCOLOR_CODNAME)


def cname(name: str, address: int | None = None):
    """regular code name"""
    if address is not None:
        return COLSTR(tag_addr(address) + name, ida_lines.SCOLOR_CNAME)
    else:
        return COLSTR(name, ida_lines.SCOLOR_CNAME)


def render_address(address: int):
    return COLSTR(tag_addr(address) + hex(address), ida_lines.SCOLOR_CREF)


def render_renamed(ev: renamed_event):
    return f"{pretty_date(ev.timestamp)}: address renamed: {cname(ev.old_name)} → {cname(ev.new_name)} at {render_address(ev.ea)}"


def render_frame_udm_renamed(ev: frame_udm_renamed_event):
    func_name = ida_funcs.get_func_name(ev.func_ea)
    return f"{pretty_date(ev.timestamp)}: local variable renamed: {cname(ev.oldname)} → {cname(ev.udm.name)} in {cname(func_name, ev.func_ea)}"


def render_event(ev: idb_event) -> str:
    if ev.event_name == "renamed":
        return render_renamed(ev)
    elif ev.event_name == "frame_udm_renamed":
        return render_frame_udm_renamed(ev)
    else:
        return f"{ev.timestamp.isoformat('T')}: {ev.event_name}"
