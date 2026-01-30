from datetime import datetime

import ida_funcs
import ida_lines
from ida_lines import COLSTR, tag_addr

from oplog_events import (
    ui_event,
    idb_event,
    renamed_event,
    make_code_event,
    make_data_event,
    func_added_event,
    segm_added_event,
    segm_moved_event,
    ti_changed_event,
    adding_segm_event,
    changing_ti_event,
    cmt_changed_event,
    sgr_changed_event,
    sgr_deleted_event,
    byte_patched_event,
    changing_cmt_event,
    dirtree_link_event,
    dirtree_move_event,
    dirtree_rank_event,
    func_deleted_event,
    func_updated_event,
    segm_deleted_event,
    set_func_end_event,
    allsegs_moved_event,
    deleting_func_event,
    deleting_segm_event,
    dirtree_mkdir_event,
    dirtree_rmdir_event,
    frame_created_event,
    frame_deleted_event,
    op_ti_changed_event,
    changing_op_ti_event,
    frame_expanded_event,
    lt_edm_changed_event,
    lt_edm_created_event,
    lt_edm_deleted_event,
    lt_edm_renamed_event,
    lt_udm_changed_event,
    lt_udm_created_event,
    lt_udm_deleted_event,
    lt_udm_renamed_event,
    set_func_start_event,
    destroyed_items_event,
    determined_main_event,
    dirtree_rminode_event,
    lt_udt_expanded_event,
    op_type_changed_event,
    stkpnts_changed_event,
    tryblks_updated_event,
    bookmark_changed_event,
    changing_op_type_event,
    deleting_tryblks_event,
    segm_end_changed_event,
    updating_tryblks_event,
    changing_segm_end_event,
    extra_cmt_changed_event,
    frame_udm_changed_event,
    frame_udm_created_event,
    frame_udm_deleted_event,
    frame_udm_renamed_event,
    func_tail_deleted_event,
    idasgn_matched_ea_event,
    range_cmt_changed_event,
    segm_name_changed_event,
    changing_range_cmt_event,
    changing_segm_name_event,
    deleting_func_tail_event,
    dirtree_segm_moved_event,
    func_noret_changed_event,
    func_tail_appended_event,
    item_color_changed_event,
    segm_attrs_updated_event,
    segm_class_changed_event,
    segm_start_changed_event,
    tail_owner_changed_event,
    thunk_func_created_event,
    callee_addr_changed_event,
    changing_segm_class_event,
    changing_segm_start_event,
    local_types_changed_event,
    current_item_changed_event,
)


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
    # TODO: when this is a function, give the function name
    return f"{pretty_date(ev.timestamp)}: address renamed: {cname(ev.old_name)} → {cname(ev.new_name)} at {render_address(ev.ea)}"


def render_frame_udm_renamed(ev: frame_udm_renamed_event):
    func_name = ida_funcs.get_func_name(ev.func_ea)
    return f"{pretty_date(ev.timestamp)}: local variable renamed: {cname(ev.oldname)} → {cname(ev.udm.name)} in {cname(func_name, ev.func_ea)}"


def render_adding_segm(ev: adding_segm_event):
    name = ev.s.segment_name if ev.s.segment_name else f"at {render_address(ev.s.start_ea)}"
    return f"{pretty_date(ev.timestamp)}: segment adding: {cname(name)} ({render_address(ev.s.start_ea)}-{render_address(ev.s.end_ea)})"


def render_segm_added(ev: segm_added_event):
    name = ev.s.segment_name if ev.s.segment_name else f"at {render_address(ev.s.start_ea)}"
    return f"{pretty_date(ev.timestamp)}: segment added: {cname(name)} ({render_address(ev.s.start_ea)}-{render_address(ev.s.end_ea)})"


def render_deleting_segm(ev: deleting_segm_event):
    # TODO: capture and render segment name
    return f"{pretty_date(ev.timestamp)}: segment deleting: at {render_address(ev.start_ea)}"


def render_segm_deleted(ev: segm_deleted_event):
    # TODO: capture and render segment name
    return f"{pretty_date(ev.timestamp)}: segment deleted: {render_address(ev.start_ea)}-{render_address(ev.end_ea)}"


def render_changing_segm_start(ev: changing_segm_start_event):
    name = ev.s.segment_name if ev.s.segment_name else f"at {render_address(ev.s.start_ea)}"
    return f"{pretty_date(ev.timestamp)}: segment start changing: {cname(name)} {render_address(ev.s.start_ea)} → {render_address(ev.new_start)}"


def render_segm_start_changed(ev: segm_start_changed_event):
    name = ev.s.segment_name if ev.s.segment_name else f"at {render_address(ev.s.start_ea)}"
    return f"{pretty_date(ev.timestamp)}: segment start changed: {cname(name)} {render_address(ev.oldstart)} → {render_address(ev.s.start_ea)}"


def render_changing_segm_end(ev: changing_segm_end_event):
    name = ev.s.segment_name if ev.s.segment_name else f"at {render_address(ev.s.start_ea)}"
    return f"{pretty_date(ev.timestamp)}: segment end changing: {cname(name)} {render_address(ev.s.end_ea)} → {render_address(ev.new_end)}"


def render_segm_end_changed(ev: segm_end_changed_event):
    name = ev.s.segment_name if ev.s.segment_name else f"at {render_address(ev.s.start_ea)}"
    return f"{pretty_date(ev.timestamp)}: segment end changed: {cname(name)} {render_address(ev.oldend)} → {render_address(ev.s.end_ea)}"


def render_changing_segm_name(ev: changing_segm_name_event):
    current_name = ev.s.segment_name if ev.s.segment_name else f"at {render_address(ev.s.start_ea)}"
    return f"{pretty_date(ev.timestamp)}: segment name changing: {cname(ev.oldname)} → {cname(current_name)}"


def render_segm_name_changed(ev: segm_name_changed_event):
    segment_desc = f"at {render_address(ev.s.start_ea)}"
    return f"{pretty_date(ev.timestamp)}: segment name changed: {segment_desc} → {cname(ev.name)}"


def render_changing_segm_class(ev: changing_segm_class_event):
    name = ev.s.segment_name if ev.s.segment_name else f"at {render_address(ev.s.start_ea)}"
    return f"{pretty_date(ev.timestamp)}: segment class changing: {cname(name)}"


def render_segm_class_changed(ev: segm_class_changed_event):
    name = ev.s.segment_name if ev.s.segment_name else f"at {render_address(ev.s.start_ea)}"
    return f"{pretty_date(ev.timestamp)}: segment class changed: {cname(name)} → {codname(ev.sclass)}"


def render_segm_attrs_updated(ev: segm_attrs_updated_event):
    name = ev.s.segment_name if ev.s.segment_name else f"at {render_address(ev.s.start_ea)}"
    return f"{pretty_date(ev.timestamp)}: segment attributes updated: {cname(name)}"


def render_segm_moved(ev: segm_moved_event):
    return f"{pretty_date(ev.timestamp)}: segment moved: {render_address(ev._from)} → {render_address(ev.to)} (size: {hex(ev.size)})"


def render_allsegs_moved(ev: allsegs_moved_event):
    return f"{pretty_date(ev.timestamp)}: rebased"


def render_func_added(ev: func_added_event):
    func_name = ida_funcs.get_func_name(ev.pfn.start_ea)
    if func_name:
        return f"{pretty_date(ev.timestamp)}: function added: {cname(func_name, ev.pfn.start_ea)} ({render_address(ev.pfn.start_ea)}-{render_address(ev.pfn.end_ea)})"
    else:
        return f"{pretty_date(ev.timestamp)}: function added: {render_address(ev.pfn.start_ea)}-{render_address(ev.pfn.end_ea)}"


def render_func_updated(ev: func_updated_event):
    # TODO: use function name at point in time
    func_name = ida_funcs.get_func_name(ev.pfn.start_ea)
    if func_name:
        return f"{pretty_date(ev.timestamp)}: function updated: {cname(func_name, ev.pfn.start_ea)}"
    else:
        return f"{pretty_date(ev.timestamp)}: function updated: {render_address(ev.pfn.start_ea)}"


def render_set_func_start(ev: set_func_start_event):
    func_name = ida_funcs.get_func_name(ev.pfn.start_ea)
    if func_name:
        return f"{pretty_date(ev.timestamp)}: function start set: {cname(func_name, ev.pfn.start_ea)} {render_address(ev.pfn.start_ea)} → {render_address(ev.new_start)}"
    else:
        return f"{pretty_date(ev.timestamp)}: function start set: {render_address(ev.pfn.start_ea)} → {render_address(ev.new_start)}"


def render_set_func_end(ev: set_func_end_event):
    func_name = ida_funcs.get_func_name(ev.pfn.start_ea)
    if func_name:
        return f"{pretty_date(ev.timestamp)}: function end set: {cname(func_name, ev.pfn.start_ea)} {render_address(ev.pfn.end_ea)} → {render_address(ev.new_end)}"
    else:
        return f"{pretty_date(ev.timestamp)}: function end set: {render_address(ev.pfn.end_ea)} → {render_address(ev.new_end)}"


def render_deleting_func(ev: deleting_func_event):
    func_name = ida_funcs.get_func_name(ev.pfn.start_ea)
    if func_name:
        return f"{pretty_date(ev.timestamp)}: function deleting: {cname(func_name, ev.pfn.start_ea)}"
    else:
        return f"{pretty_date(ev.timestamp)}: function deleting: {render_address(ev.pfn.start_ea)}"


def render_func_deleted(ev: func_deleted_event):
    return f"{pretty_date(ev.timestamp)}: function deleted: {render_address(ev.func_ea)}"


def render_thunk_func_created(ev: thunk_func_created_event):
    func_name = ida_funcs.get_func_name(ev.pfn.start_ea)
    if func_name:
        return f"{pretty_date(ev.timestamp)}: thunk function created: {cname(func_name, ev.pfn.start_ea)}"
    else:
        return f"{pretty_date(ev.timestamp)}: thunk function created: {render_address(ev.pfn.start_ea)}"


def render_func_tail_appended(ev: func_tail_appended_event):
    func_name = ida_funcs.get_func_name(ev.pfn.start_ea)
    tail_name = ida_funcs.get_func_name(ev.tail.start_ea)
    if func_name and tail_name:
        return f"{pretty_date(ev.timestamp)}: function tail appended: {cname(tail_name, ev.tail.start_ea)} → {cname(func_name, ev.pfn.start_ea)}"
    elif func_name:
        return f"{pretty_date(ev.timestamp)}: function tail appended: {render_address(ev.tail.start_ea)} → {cname(func_name, ev.pfn.start_ea)}"
    elif tail_name:
        return f"{pretty_date(ev.timestamp)}: function tail appended: {cname(tail_name, ev.tail.start_ea)} → {render_address(ev.pfn.start_ea)}"
    else:
        return f"{pretty_date(ev.timestamp)}: function tail appended: {render_address(ev.tail.start_ea)} → {render_address(ev.pfn.start_ea)}"


def render_deleting_func_tail(ev: deleting_func_tail_event):
    func_name = ida_funcs.get_func_name(ev.pfn.start_ea)
    if func_name:
        return f"{pretty_date(ev.timestamp)}: function tail deleting: {render_address(ev.tail.start_ea)} from {cname(func_name, ev.pfn.start_ea)}"
    else:
        return f"{pretty_date(ev.timestamp)}: function tail deleting: {render_address(ev.tail.start_ea)} from {render_address(ev.pfn.start_ea)}"


def render_func_tail_deleted(ev: func_tail_deleted_event):
    func_name = ida_funcs.get_func_name(ev.pfn.start_ea)
    if func_name:
        return f"{pretty_date(ev.timestamp)}: function tail deleted: {render_address(ev.tail_ea)} from {cname(func_name, ev.pfn.start_ea)}"
    else:
        return f"{pretty_date(ev.timestamp)}: function tail deleted: {render_address(ev.tail_ea)} from {render_address(ev.pfn.start_ea)}"


def render_tail_owner_changed(ev: tail_owner_changed_event):
    tail_name = ida_funcs.get_func_name(ev.tail.start_ea)
    old_owner_name = ida_funcs.get_func_name(ev.old_owner)
    new_owner_name = ida_funcs.get_func_name(ev.owner_func)

    tail_desc = cname(tail_name, ev.tail.start_ea) if tail_name else render_address(ev.tail.start_ea)
    old_desc = cname(old_owner_name, ev.old_owner) if old_owner_name else render_address(ev.old_owner)
    new_desc = cname(new_owner_name, ev.owner_func) if new_owner_name else render_address(ev.owner_func)

    return f"{pretty_date(ev.timestamp)}: tail owner changed: {tail_desc} {old_desc} → {new_desc}"


def render_func_noret_changed(ev: func_noret_changed_event):
    func_name = ida_funcs.get_func_name(ev.pfn.start_ea)
    if func_name:
        return f"{pretty_date(ev.timestamp)}: function noret changed: {cname(func_name, ev.pfn.start_ea)}"
    else:
        return f"{pretty_date(ev.timestamp)}: function noret changed: {render_address(ev.pfn.start_ea)}"


def render_updating_tryblks(ev: updating_tryblks_event):
    # TODO: describe which function
    return f"{pretty_date(ev.timestamp)}: tryblks updating"


def render_tryblks_updated(ev: tryblks_updated_event):
    # TODO: describe which function
    return f"{pretty_date(ev.timestamp)}: tryblks updated"


def render_deleting_tryblks(ev: deleting_tryblks_event):
    # TODO: describe which function
    return f"{pretty_date(ev.timestamp)}: tryblks deleting: {render_address(ev.range.start_ea)}-{render_address(ev.range.end_ea)}"


def render_changing_cmt(ev: changing_cmt_event):
    # TODO: capture and render comment text
    cmt_type = "repeatable comment" if ev.repeatable_cmt else "comment"
    return f"{pretty_date(ev.timestamp)}: {cmt_type} changing: {render_address(ev.ea)}"


def render_cmt_changed(ev: cmt_changed_event):
    # TODO: capture and render comment text
    cmt_type = "repeatable comment" if ev.repeatable_cmt else "comment"
    return f"{pretty_date(ev.timestamp)}: {cmt_type} changed: {render_address(ev.ea)}"


def render_changing_range_cmt(ev: changing_range_cmt_event):
    # TODO: what is a range comment?
    # TODO: capture and render comment text
    cmt_type = "repeatable range comment" if ev.repeatable else "range comment"
    return f"{pretty_date(ev.timestamp)}: {cmt_type} changing: {render_address(ev.a.start_ea)}-{render_address(ev.a.end_ea)}"


def render_range_cmt_changed(ev: range_cmt_changed_event):
    # TODO: capture and render comment text
    cmt_type = "repeatable range comment" if ev.repeatable else "range comment"
    return f"{pretty_date(ev.timestamp)}: {cmt_type} changed: {render_address(ev.a.start_ea)}-{render_address(ev.a.end_ea)}"


def render_extra_cmt_changed(ev: extra_cmt_changed_event):
    # TODO: capture and render comment text
    return f"{pretty_date(ev.timestamp)}: extra comment changed: {render_address(ev.ea)} line {ev.line_idx}"


def render_sgr_changed(ev: sgr_changed_event):
    # TODO: render segment register name (e.g., CS, DS, ...)
    return f"{pretty_date(ev.timestamp)}: segment register changed: {render_address(ev.start_ea)}-{render_address(ev.end_ea)} reg{ev.regnum}"


def render_sgr_deleted(ev: sgr_deleted_event):
    return f"{pretty_date(ev.timestamp)}: segment register deleted: {render_address(ev.start_ea)}-{render_address(ev.end_ea)} reg{ev.regnum}"


def render_make_code(ev: make_code_event):
    return f"{pretty_date(ev.timestamp)}: code created: {render_address(ev.insn.ea)}"


def render_make_data(ev: make_data_event):
    type_desc = f" as {codname(ev.type_name)}" if ev.type_name != "(unnamed)" else ""
    return f"{pretty_date(ev.timestamp)}: data created: {render_address(ev.ea)}{type_desc} (size: {ev.len})"


def render_destroyed_items(ev: destroyed_items_event):
    return f"{pretty_date(ev.timestamp)}: items destroyed: {render_address(ev.ea1)}-{render_address(ev.ea2)}"


def render_byte_patched(ev: byte_patched_event):
    # TODO: capture and render new byte
    return f"{pretty_date(ev.timestamp)}: byte patched: {render_address(ev.ea)} {hex(ev.old_value)} → ?"


def render_item_color_changed(ev: item_color_changed_event):
    return f"{pretty_date(ev.timestamp)}: item color changed: {render_address(ev.ea)}"


def render_callee_addr_changed(ev: callee_addr_changed_event):
    callee_name = ida_funcs.get_func_name(ev.callee)
    if callee_name:
        return f"{pretty_date(ev.timestamp)}: callee address changed: {render_address(ev.ea)} → {cname(callee_name, ev.callee)}"
    else:
        return f"{pretty_date(ev.timestamp)}: callee address changed: {render_address(ev.ea)} → {render_address(ev.callee)}"


def render_bookmark_changed(ev: bookmark_changed_event):
    return f'{pretty_date(ev.timestamp)}: bookmark changed: {render_address(ev.ea)} "{ev.desc}"'


def render_changing_op_type(ev: changing_op_type_event):
    # TODO: capture and render operand type (e.g., imm -> offset)
    return f"{pretty_date(ev.timestamp)}: operand type changing: {render_address(ev.ea)} op{ev.n}"


def render_op_type_changed(ev: op_type_changed_event):
    # TODO: capture and render operand type (e.g., imm -> offset)
    return f"{pretty_date(ev.timestamp)}: operand type changed: {render_address(ev.ea)} op{ev.n}"


def render_dirtree_mkdir(ev: dirtree_mkdir_event):
    return f"{pretty_date(ev.timestamp)}: directory created: {codname(ev.path)}"


def render_dirtree_rmdir(ev: dirtree_rmdir_event):
    return f"{pretty_date(ev.timestamp)}: directory removed: {codname(ev.path)}"


def render_dirtree_link(ev: dirtree_link_event):
    action = "linked" if ev.link else "unlinked"
    return f"{pretty_date(ev.timestamp)}: directory {action}: {codname(ev.path)}"


def render_dirtree_move(ev: dirtree_move_event):
    return f"{pretty_date(ev.timestamp)}: directory moved: {codname(ev._from)} → {codname(ev.to)}"


def render_dirtree_rank(ev: dirtree_rank_event):
    return f"{pretty_date(ev.timestamp)}: directory ranked: {codname(ev.path)} (rank: {ev.rank})"


def render_dirtree_rminode(ev: dirtree_rminode_event):
    return f"{pretty_date(ev.timestamp)}: directory inode removed: {ev.inode}"


def render_dirtree_segm_moved(ev: dirtree_segm_moved_event):
    return f"{pretty_date(ev.timestamp)}: directory segment moved"


def render_changing_ti(ev: changing_ti_event):
    # TODO: describe the old and new type
    # TODO: describe the address (variable/name/function)
    return f"{pretty_date(ev.timestamp)}: type information changing: {render_address(ev.ea)}"


def render_ti_changed(ev: ti_changed_event):
    # TODO: describe the new type
    # TODO: describe the address (variable/name/function)
    return f"{pretty_date(ev.timestamp)}: type information changed: {render_address(ev.ea)}"


def render_changing_op_ti(ev: changing_op_ti_event):
    # TODO: describe the new type
    # TODO: describe the address (variable/name/function)
    return f"{pretty_date(ev.timestamp)}: operand type information changing: {render_address(ev.ea)} op{ev.n}"


def render_op_ti_changed(ev: op_ti_changed_event):
    # TODO: describe the new type
    # TODO: describe the address (variable/name/function)
    return f"{pretty_date(ev.timestamp)}: operand type information changed: {render_address(ev.ea)} op{ev.n}"


def render_local_types_changed(ev: local_types_changed_event):
    # TODO: describe the type changes
    return f"{pretty_date(ev.timestamp)}: local types changed: {codname(ev.name or "")} (ordinal: {ev.ordinal})"


def render_lt_udm_created(ev: lt_udm_created_event):
    type_desc = f": {codname(ev.udm.type_name)}" if ev.udm.type_name != "(unnamed)" else ""
    return f"{pretty_date(ev.timestamp)}: struct member created: {codname(ev.udm.name)}{type_desc} in {codname(ev.udtname)}"


def render_lt_udm_deleted(ev: lt_udm_deleted_event):
    type_desc = f": {codname(ev.udm.type_name)}" if ev.udm.type_name != "(unnamed)" else ""
    return f"{pretty_date(ev.timestamp)}: struct member deleted: {codname(ev.udm.name)}{type_desc} from {codname(ev.udtname)}"


def render_lt_udm_renamed(ev: lt_udm_renamed_event):
    return f"{pretty_date(ev.timestamp)}: struct member renamed: {codname(ev.oldname)} → {codname(ev.udm.name)} in {codname(ev.udtname)}"


def render_lt_udm_changed(ev: lt_udm_changed_event):
    changes = []
    if ev.udmold.type_name != ev.udmnew.type_name:
        changes.append(f"type: {codname(ev.udmold.type_name)} → {codname(ev.udmnew.type_name)}")
    if ev.udmold.size != ev.udmnew.size:
        changes.append(f"size: {ev.udmold.size} → {ev.udmnew.size}")
    if ev.udmold.cmt != ev.udmnew.cmt:
        changes.append("comment")
    change_desc = f" ({', '.join(changes)})" if changes else ""
    return f"{pretty_date(ev.timestamp)}: struct member changed: {codname(ev.udmnew.name)} in {codname(ev.udtname)}{change_desc}"


def render_lt_udt_expanded(ev: lt_udt_expanded_event):
    member_desc = f" before {codname(ev.udm_name)}" if ev.udm_name != "(unnamed)" else ""
    return f"{pretty_date(ev.timestamp)}: struct expanded: {codname(ev.udtname)}{member_desc} (delta: {ev.delta})"


def render_lt_edm_created(ev: lt_edm_created_event):
    return f"{pretty_date(ev.timestamp)}: enum member created: {codname(ev.edm.name)} in {codname(ev.enumname)} (value: {ev.edm.value})"


def render_lt_edm_deleted(ev: lt_edm_deleted_event):
    return f"{pretty_date(ev.timestamp)}: enum member deleted: {codname(ev.edm.name)} from {codname(ev.enumname)}"


def render_lt_edm_renamed(ev: lt_edm_renamed_event):
    return f"{pretty_date(ev.timestamp)}: enum member renamed: {codname(ev.oldname)} → {codname(ev.edm.name)} in {codname(ev.enumname)}"


def render_lt_edm_changed(ev: lt_edm_changed_event):
    return f"{pretty_date(ev.timestamp)}: enum member changed: {codname(ev.edmnew.name)} in {codname(ev.enumname)} (value: {ev.edmnew.value})"


def render_stkpnts_changed(ev: stkpnts_changed_event):
    func_name = ida_funcs.get_func_name(ev.pfn.start_ea)
    if func_name:
        return f"{pretty_date(ev.timestamp)}: stack points changed: {cname(func_name, ev.pfn.start_ea)}"
    else:
        return f"{pretty_date(ev.timestamp)}: stack points changed: {render_address(ev.pfn.start_ea)}"


def render_frame_created(ev: frame_created_event):
    # TODO: capture func name into event
    func_name = ida_funcs.get_func_name(ev.func_ea)
    if func_name:
        return f"{pretty_date(ev.timestamp)}: frame created: {cname(func_name, ev.func_ea)}"
    else:
        return f"{pretty_date(ev.timestamp)}: frame created: {render_address(ev.func_ea)}"


def render_frame_expanded(ev: frame_expanded_event):
    func_name = ida_funcs.get_func_name(ev.func_ea)
    func_desc = cname(func_name, ev.func_ea) if func_name else render_address(ev.func_ea)
    member_desc = f" before {cname(ev.udm_name)}" if ev.udm_name != "(unnamed)" else ""
    return f"{pretty_date(ev.timestamp)}: frame expanded: {func_desc}{member_desc} (delta: {ev.delta})"


def render_frame_deleted(ev: frame_deleted_event):
    # TODO: capture func name into event
    func_name = ida_funcs.get_func_name(ev.pfn.start_ea)
    if func_name:
        return f"{pretty_date(ev.timestamp)}: frame deleted: {cname(func_name, ev.pfn.start_ea)}"
    else:
        return f"{pretty_date(ev.timestamp)}: frame deleted: {render_address(ev.pfn.start_ea)}"


def render_frame_udm_created(ev: frame_udm_created_event):
    func_name = ida_funcs.get_func_name(ev.func_ea)
    func_desc = cname(func_name, ev.func_ea) if func_name else render_address(ev.func_ea)
    type_desc = f": {codname(ev.udm.type_name)}" if ev.udm.type_name != "(unnamed)" else ""
    return f"{pretty_date(ev.timestamp)}: local variable created: {cname(ev.udm.name)}{type_desc} in {func_desc}"


def render_frame_udm_deleted(ev: frame_udm_deleted_event):
    func_name = ida_funcs.get_func_name(ev.func_ea)
    func_desc = cname(func_name, ev.func_ea) if func_name else render_address(ev.func_ea)
    type_desc = f": {codname(ev.udm.type_name)}" if ev.udm.type_name != "(unnamed)" else ""
    return f"{pretty_date(ev.timestamp)}: local variable deleted: {cname(ev.udm.name)}{type_desc} from {func_desc}"


def render_frame_udm_changed(ev: frame_udm_changed_event):
    func_name = ida_funcs.get_func_name(ev.func_ea)
    func_desc = cname(func_name, ev.func_ea) if func_name else render_address(ev.func_ea)
    changes = []
    if ev.udmold.type_name != ev.udmnew.type_name:
        changes.append(f"type: {codname(ev.udmold.type_name)} → {codname(ev.udmnew.type_name)}")
    if ev.udmold.size != ev.udmnew.size:
        changes.append(f"size: {ev.udmold.size} → {ev.udmnew.size}")
    if ev.udmold.cmt != ev.udmnew.cmt:
        changes.append("comment")
    change_desc = f" ({', '.join(changes)})" if changes else ""
    return f"{pretty_date(ev.timestamp)}: local variable changed: {cname(ev.udmnew.name)} in {func_desc}{change_desc}"


def render_determined_main(ev: determined_main_event):
    # TODO: capture func name into event
    func_name = ida_funcs.get_func_name(ev.main)
    if func_name:
        return f"{pretty_date(ev.timestamp)}: main function determined: {cname(func_name, ev.main)}"
    else:
        return f"{pretty_date(ev.timestamp)}: main function determined: {render_address(ev.main)}"


def render_idasgn_matched_ea(ev: idasgn_matched_ea_event):
    return f"{pretty_date(ev.timestamp)}: signature matched: {cname(ev.name, ev.ea)} from {codname(ev.lib_name)}"


def render_current_item_changed(ev: current_item_changed_event):
    return f"{pretty_date(ev.timestamp)}: navigate: {cname(ev.prev_item_name, ev.prev_item_ea)} → {cname(ev.current_item_name, ev.current_item_ea)}"


def render_event(ev: idb_event | ui_event) -> str:
    if ev.event_name == "renamed":
        return render_renamed(ev)
    elif ev.event_name == "frame_udm_renamed":
        return render_frame_udm_renamed(ev)
    elif ev.event_name == "adding_segm":
        return render_adding_segm(ev)
    elif ev.event_name == "segm_added":
        return render_segm_added(ev)
    elif ev.event_name == "deleting_segm":
        return render_deleting_segm(ev)
    elif ev.event_name == "segm_deleted":
        return render_segm_deleted(ev)
    elif ev.event_name == "changing_segm_start":
        return render_changing_segm_start(ev)
    elif ev.event_name == "segm_start_changed":
        return render_segm_start_changed(ev)
    elif ev.event_name == "changing_segm_end":
        return render_changing_segm_end(ev)
    elif ev.event_name == "segm_end_changed":
        return render_segm_end_changed(ev)
    elif ev.event_name == "changing_segm_name":
        return render_changing_segm_name(ev)
    elif ev.event_name == "segm_name_changed":
        return render_segm_name_changed(ev)
    elif ev.event_name == "changing_segm_class":
        return render_changing_segm_class(ev)
    elif ev.event_name == "segm_class_changed":
        return render_segm_class_changed(ev)
    elif ev.event_name == "segm_attrs_updated":
        return render_segm_attrs_updated(ev)
    elif ev.event_name == "segm_moved":
        return render_segm_moved(ev)
    elif ev.event_name == "allsegs_moved":
        return render_allsegs_moved(ev)
    elif ev.event_name == "func_added":
        return render_func_added(ev)
    elif ev.event_name == "func_updated":
        return render_func_updated(ev)
    elif ev.event_name == "set_func_start":
        return render_set_func_start(ev)
    elif ev.event_name == "set_func_end":
        return render_set_func_end(ev)
    elif ev.event_name == "deleting_func":
        return render_deleting_func(ev)
    elif ev.event_name == "func_deleted":
        return render_func_deleted(ev)
    elif ev.event_name == "thunk_func_created":
        return render_thunk_func_created(ev)
    elif ev.event_name == "func_tail_appended":
        return render_func_tail_appended(ev)
    elif ev.event_name == "deleting_func_tail":
        return render_deleting_func_tail(ev)
    elif ev.event_name == "func_tail_deleted":
        return render_func_tail_deleted(ev)
    elif ev.event_name == "tail_owner_changed":
        return render_tail_owner_changed(ev)
    elif ev.event_name == "func_noret_changed":
        return render_func_noret_changed(ev)
    elif ev.event_name == "updating_tryblks":
        return render_updating_tryblks(ev)
    elif ev.event_name == "tryblks_updated":
        return render_tryblks_updated(ev)
    elif ev.event_name == "deleting_tryblks":
        return render_deleting_tryblks(ev)
    elif ev.event_name == "changing_cmt":
        return render_changing_cmt(ev)
    elif ev.event_name == "cmt_changed":
        return render_cmt_changed(ev)
    elif ev.event_name == "changing_range_cmt":
        return render_changing_range_cmt(ev)
    elif ev.event_name == "range_cmt_changed":
        return render_range_cmt_changed(ev)
    elif ev.event_name == "extra_cmt_changed":
        return render_extra_cmt_changed(ev)
    elif ev.event_name == "sgr_changed":
        return render_sgr_changed(ev)
    elif ev.event_name == "sgr_deleted":
        return render_sgr_deleted(ev)
    elif ev.event_name == "make_code":
        return render_make_code(ev)
    elif ev.event_name == "make_data":
        return render_make_data(ev)
    elif ev.event_name == "destroyed_items":
        return render_destroyed_items(ev)
    elif ev.event_name == "byte_patched":
        return render_byte_patched(ev)
    elif ev.event_name == "item_color_changed":
        return render_item_color_changed(ev)
    elif ev.event_name == "callee_addr_changed":
        return render_callee_addr_changed(ev)
    elif ev.event_name == "bookmark_changed":
        return render_bookmark_changed(ev)
    elif ev.event_name == "changing_op_type":
        return render_changing_op_type(ev)
    elif ev.event_name == "op_type_changed":
        return render_op_type_changed(ev)
    elif ev.event_name == "dirtree_mkdir":
        return render_dirtree_mkdir(ev)
    elif ev.event_name == "dirtree_rmdir":
        return render_dirtree_rmdir(ev)
    elif ev.event_name == "dirtree_link":
        return render_dirtree_link(ev)
    elif ev.event_name == "dirtree_move":
        return render_dirtree_move(ev)
    elif ev.event_name == "dirtree_rank":
        return render_dirtree_rank(ev)
    elif ev.event_name == "dirtree_rminode":
        return render_dirtree_rminode(ev)
    elif ev.event_name == "dirtree_segm_moved":
        return render_dirtree_segm_moved(ev)
    elif ev.event_name == "changing_ti":
        return render_changing_ti(ev)
    elif ev.event_name == "ti_changed":
        return render_ti_changed(ev)
    elif ev.event_name == "changing_op_ti":
        return render_changing_op_ti(ev)
    elif ev.event_name == "op_ti_changed":
        return render_op_ti_changed(ev)
    elif ev.event_name == "local_types_changed":
        return render_local_types_changed(ev)
    elif ev.event_name == "lt_udm_created":
        return render_lt_udm_created(ev)
    elif ev.event_name == "lt_udm_deleted":
        return render_lt_udm_deleted(ev)
    elif ev.event_name == "lt_udm_renamed":
        return render_lt_udm_renamed(ev)
    elif ev.event_name == "lt_udm_changed":
        return render_lt_udm_changed(ev)
    elif ev.event_name == "lt_udt_expanded":
        return render_lt_udt_expanded(ev)
    elif ev.event_name == "lt_edm_created":
        return render_lt_edm_created(ev)
    elif ev.event_name == "lt_edm_deleted":
        return render_lt_edm_deleted(ev)
    elif ev.event_name == "lt_edm_renamed":
        return render_lt_edm_renamed(ev)
    elif ev.event_name == "lt_edm_changed":
        return render_lt_edm_changed(ev)
    elif ev.event_name == "stkpnts_changed":
        return render_stkpnts_changed(ev)
    elif ev.event_name == "frame_created":
        return render_frame_created(ev)
    elif ev.event_name == "frame_expanded":
        return render_frame_expanded(ev)
    elif ev.event_name == "frame_deleted":
        return render_frame_deleted(ev)
    elif ev.event_name == "frame_udm_created":
        return render_frame_udm_created(ev)
    elif ev.event_name == "frame_udm_deleted":
        return render_frame_udm_deleted(ev)
    elif ev.event_name == "frame_udm_changed":
        return render_frame_udm_changed(ev)
    elif ev.event_name == "determined_main":
        return render_determined_main(ev)
    elif ev.event_name == "idasgn_matched_ea":
        return render_idasgn_matched_ea(ev)
    elif ev.event_name == "current_item_changed":
        return render_current_item_changed(ev)
    else:
        return f"{ev.timestamp.isoformat('T')}: {ev.event_name}"
