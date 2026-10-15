#!/usr/bin/env python
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "rich",
#     "ida-domain>=0.5",
# ]
# ///
"""
Annotate functions with the metadata that the Lumina servers hold for them.

For each function, query the primary and secondary Lumina servers (when configured)
and write a summary of each record into the function comment: the name, frequency,
score, prototype, function comments, and counts of the remaining metadata,
followed by the timeline of earlier versions.
The script does not apply the metadata itself.

IDAPython does not wrap the history request, so the script calls
ida_lumina_client_t::get_func_histories through the C++ vtable with ctypes.
This depends on the IDA version and supports IDA 9.5 on macOS and Linux.

Run from IDA via File > Script file, or standalone via idalib:

    uv run scripts/lumina_metadata/lumina_metadata.py path/to/input.exe
"""

import argparse
import ctypes
import dataclasses
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ida_domain import Database
from ida_domain.database import IdaCommandOptions

# isort: split
import ida_diskio
import ida_kernwin
import ida_lumina
import ida_pro
import ida_typeinf

logger = logging.getLogger("lumina_metadata")

COMMENT_HEADER_PREFIX = "Lumina "
COMMENT_HEADER = re.compile(r"^Lumina (primary|secondary): ")
MAX_TEXT_LENGTH = 200
MAX_FRAME_MEMBERS = 8
MAX_HISTORY_ENTRIES = 10

PKT_GET_FUNC_HISTORIES_RESULT = 48
GET_FUNC_HISTORIES_VTABLE_SLOTS = {"9.5": 14}
RPC_PACKET_DELETING_DESTRUCTOR_SLOT = 1
LIBIDA_NAMES = {"darwin": "libida.dylib", "linux": "libida.so"}


@dataclass
class InstructionComment:
    ea: int
    text: str
    repeatable: bool


@dataclass
class ExtraComment:
    ea: int
    anterior: str
    posterior: str


@dataclass
class FrameMember:
    offset: int
    name: str
    comment: str


@dataclass
class FunctionMetadata:
    prototype: str = ""
    function_comment: str = ""
    repeatable_function_comment: str = ""
    instruction_comments: list[InstructionComment] = field(default_factory=list)
    extra_comments: list[ExtraComment] = field(default_factory=list)
    frame_members: list[FrameMember] = field(default_factory=list)
    operand_representation_count: int = 0
    user_stack_point_count: int = 0

    @classmethod
    def from_bytes(cls, name: str, func_ea: int, data: bytes) -> "FunctionMetadata":
        md = ida_lumina.split_metadata(data)
        metadata = cls()

        if ida_lumina.MDK_TYPE in md:
            tif = ida_typeinf.tinfo_t()
            ida_lumina.extract_type_from_metadata(tif, md[ida_lumina.MDK_TYPE])
            if not tif.empty():
                metadata.prototype = tif._print(
                    name, ida_typeinf.PRTYPE_1LINE | ida_typeinf.PRTYPE_SEMI
                ).rstrip(";")

        metadata.function_comment = md.get(ida_lumina.MDK_FCMT, b"").decode(
            "utf-8", errors="replace"
        )
        metadata.repeatable_function_comment = md.get(
            ida_lumina.MDK_FRPTCMT, b""
        ).decode("utf-8", errors="replace")

        for key, repeatable in (
            (ida_lumina.MDK_CMTS, False),
            (ida_lumina.MDK_RPTCMTS, True),
        ):
            if key in md:
                cmts = ida_lumina.insn_cmts_t()
                ida_lumina.extract_insn_cmts_from_metadata(cmts, md[key])
                metadata.instruction_comments.extend(
                    InstructionComment(
                        ea=c.to_ea(func_ea), text=c.cmt, repeatable=repeatable
                    )
                    for c in cmts
                )

        if ida_lumina.MDK_EXTRACMTS in md:
            extras = ida_lumina.extra_cmts_t()
            ida_lumina.extract_extra_cmts_from_metadata(
                extras, md[ida_lumina.MDK_EXTRACMTS]
            )
            metadata.extra_comments = [
                ExtraComment(ea=c.to_ea(func_ea), anterior=c.prev, posterior=c.next)
                for c in extras
            ]

        if ida_lumina.MDK_FRAME_DESC in md:
            frame = ida_lumina.frame_desc_t()
            ida_lumina.extract_frame_desc_from_metadata(
                frame, md[ida_lumina.MDK_FRAME_DESC]
            )
            metadata.frame_members = [
                FrameMember(offset=m.offset, name=m.name, comment=m.cmt or m.rptcmt)
                for m in frame.members
                if m.name or m.cmt or m.rptcmt
            ]

        for key, extract in (
            (ida_lumina.MDK_OPS, ida_lumina.extract_insn_opreprs_from_metadata),
            (ida_lumina.MDK_OPS_EX, ida_lumina.extract_insn_opreprs_from_metadata_ex),
        ):
            if key in md:
                ops = ida_lumina.insn_ops_reprs_t()
                extract(ops, md[key])
                metadata.operand_representation_count += len(ops)

        if ida_lumina.MDK_USER_STKPNTS in md:
            stkpnts = ida_lumina.user_stkpnts_t()
            ida_lumina.extract_user_stkpnts_from_metadata(
                stkpnts, md[ida_lumina.MDK_USER_STKPNTS]
            )
            metadata.user_stack_point_count = len(stkpnts)

        return metadata


@dataclass
class HistoryEntry:
    """
    One version of a function in the Lumina history.
    """

    timestamp: datetime
    name: str
    metadata: FunctionMetadata = field(default_factory=FunctionMetadata)


@dataclass
class LuminaRecord:
    """
    The metadata that one Lumina server holds for one function.

    Lumina keeps one record per function hash and server. `frequency` counts how
    often clients pulled the record; `score` is IDA's quality estimate of the metadata.
    `history` lists all versions of the record, newest first; the first entry is the current version.
    """

    server: str
    name: str
    size: int
    frequency: int
    score: int
    metadata: FunctionMetadata = field(default_factory=FunctionMetadata)
    history: list[HistoryEntry] = field(default_factory=list)

    @classmethod
    def from_func_info(
        cls, server: str, func_ea: int, fi: "ida_lumina.func_info_and_frequency_t"
    ) -> "LuminaRecord":
        return cls(
            server=server,
            name=fi.name,
            size=fi.size,
            frequency=fi.frequency,
            score=ida_lumina.score_metadata(fi),
            metadata=FunctionMetadata.from_bytes(fi.name, func_ea, bytes(fi.metadata)),
        )


class QVector(ctypes.Structure):
    """
    The memory layout of the SDK qvector<T>, which also backs qstring and bytevec_t.
    """

    _fields_ = [
        ("array", ctypes.c_void_p),
        ("n", ctypes.c_size_t),
        ("alloc", ctypes.c_size_t),
    ]

    def get_bytes(self) -> bytes:
        return ctypes.string_at(self.array, self.n) if self.n else b""

    def get_str(self) -> str:
        return self.get_bytes().rstrip(b"\0").decode("utf-8", errors="replace")

    def get_items(self, ctype):
        return (ctype * self.n).from_address(self.array) if self.n else []


class FuncHistoryEntry(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("func_ea", ctypes.c_uint64),
        ("name", QVector),
        ("metadata", QVector),
        ("ts", ctypes.c_uint64),
        ("author_idx", ctypes.c_int32),
        ("idb_path_idx", ctypes.c_int32),
    ]


class FuncHistoriesResult(ctypes.Structure):
    """
    The memory layout of pkt_get_func_histories_result_t.
    """

    _fields_ = [
        ("vtable", ctypes.c_void_p),
        ("code", ctypes.c_uint8),
        ("pattern_idx_to_entries_idx", QVector),
        ("func_history_entries_vec", QVector),
    ]


def get_timestamp(ts: int) -> datetime:
    """
    Convert a qtime64_t, which holds seconds in the high 32 bits and microseconds in the low 32 bits.
    """
    return datetime.fromtimestamp(ts >> 32, UTC) + timedelta(
        microseconds=ts & 0xFFFFFFFF
    )


def get_history_entries(
    result: FuncHistoriesResult, func_eas: list[int]
) -> dict[int, list[HistoryEntry]]:
    """
    Read the timelines from a GET_FUNC_HISTORIES result, for the functions that have one.

    Raises:
        RuntimeError: if the result is malformed.
    """
    if result.code != PKT_GET_FUNC_HISTORIES_RESULT:
        raise RuntimeError(f"unexpected Lumina response: packet type {result.code}")

    indexes = list(result.pattern_idx_to_entries_idx.get_items(ctypes.c_int32))
    if len(indexes) != len(func_eas):
        raise RuntimeError(
            f"unexpected Lumina response: {len(indexes)} functions in the response for {len(func_eas)} in the request"
        )

    timelines = result.func_history_entries_vec.get_items(QVector)
    histories = {}
    for ea, index in zip(func_eas, indexes):
        if index < 0:
            continue
        if index >= len(timelines):
            raise RuntimeError(
                f"unexpected Lumina response: history index {index} out of {len(timelines)}"
            )

        entries = []
        for e in timelines[index].get_items(FuncHistoryEntry):
            name = e.name.get_str()
            entries.append(
                HistoryEntry(
                    timestamp=get_timestamp(e.ts),
                    name=name,
                    metadata=FunctionMetadata.from_bytes(
                        name, ea, e.metadata.get_bytes()
                    ),
                )
            )
        histories[ea] = entries
    return histories


def get_libida() -> ctypes.CDLL:
    """
    Raises:
        RuntimeError: on platforms with an unknown C++ ABI.
    """
    name = LIBIDA_NAMES.get(sys.platform)
    if name is None:
        raise RuntimeError(f"Lumina history is not supported on {sys.platform}")
    libida = ctypes.CDLL(str(Path(ida_diskio.idadir(None)) / name))
    libida.qfree.argtypes = [ctypes.c_void_p]
    libida.qfree.restype = None
    return libida


def get_virtual_function(obj: int, slot: int) -> int:
    """
    Get the address of a virtual function of a C++ object, using the Itanium ABI layout.

    Raises:
        RuntimeError: if the vtable or the slot is null.
    """
    vtable = ctypes.c_void_p.from_address(obj).value
    if not vtable:
        raise RuntimeError(f"C++ object at {obj:#x} has no vtable")
    fn = ctypes.c_void_p.from_address(
        vtable + slot * ctypes.sizeof(ctypes.c_void_p)
    ).value
    if not fn:
        raise RuntimeError(f"C++ object at {obj:#x} has no virtual function {slot}")
    return fn


def get_func_histories(
    client: "ida_lumina.lumina_client_t", func_eas: list[int]
) -> dict[int, list[HistoryEntry]]:
    """
    Fetch the Lumina history of the given functions, the data behind IDA's "Lumina > Metadata History" view.

    Raises:
        RuntimeError: if this IDA version is not supported, the server rejects the request,
            or the response is malformed.
    """
    version = ida_kernwin.get_kernel_version()
    slot = GET_FUNC_HISTORIES_VTABLE_SLOTS.get(version)
    if slot is None:
        raise RuntimeError(f"Lumina history is not supported on IDA {version}")
    libida = get_libida()

    this = int(client.this)
    get_func_histories_fn = ctypes.CFUNCTYPE(
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p
    )(get_virtual_function(this, slot))

    eas = (ctypes.c_uint64 * len(func_eas))(*func_eas)
    eavec = QVector(ctypes.addressof(eas), len(func_eas), len(func_eas))
    errbuf = QVector()
    result_ptr = get_func_histories_fn(this, ctypes.byref(errbuf), ctypes.byref(eavec))
    error = errbuf.get_str()
    if errbuf.array:
        libida.qfree(errbuf.array)
    if not result_ptr:
        raise RuntimeError(f"Lumina history request failed: {error or 'no response'}")

    result = FuncHistoriesResult.from_address(result_ptr)
    try:
        return get_history_entries(result, func_eas)
    finally:
        deleting_destructor = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(
            get_virtual_function(result_ptr, RPC_PACKET_DELETING_DESTRUCTOR_SLOT)
        )
        deleting_destructor(result_ptr)


def get_lumina_clients() -> dict[str, "ida_lumina.lumina_client_t"]:
    """
    Connect to the configured Lumina servers.

    Raises:
        RuntimeError: if no Lumina server is configured or reachable.
    """
    clients = {}
    for server, feature in (
        ("primary", ida_lumina.LFEAT_PRIMARY_MD),
        ("secondary", ida_lumina.LFEAT_SECONDARY_MD),
    ):
        client = ida_lumina.get_server_connection2(feature)
        if client is None:
            logger.debug("no connection to the %s Lumina server", server)
            continue
        clients[server] = client

    if not clients:
        raise RuntimeError(
            "no Lumina server is configured or reachable (see LUMINA_PRIMARY)"
        )
    return clients


def get_lumina_records(
    client: "ida_lumina.lumina_client_t", server: str, func_eas: list[int]
) -> dict[int, LuminaRecord]:
    """
    Pull the records for the given functions without applying them.

    The request sets PULL_MD_SEEN_FILE so that it does not increase the frequency counters on the server.
    """
    eas = ida_pro.eavec_t()
    for ea in func_eas:
        eas.push_back(ea)

    result = client.pull_md(eas, ida_lumina.PULL_MD_SEEN_FILE)
    codes = list(result.codes)
    if len(codes) != len(func_eas):
        raise RuntimeError(
            f"unexpected Lumina response: {len(codes)} status codes for {len(func_eas)} functions"
        )

    found = [ea for ea, code in zip(func_eas, codes) if code == ida_lumina.PDRES_OK]
    if len(found) != len(result.results):
        raise RuntimeError(
            f"unexpected Lumina response: {len(result.results)} records for {len(found)} matches"
        )

    return {
        ea: LuminaRecord.from_func_info(server, ea, fi)
        for ea, fi in zip(found, result.results)
    }


def render_text(text: str) -> str:
    text = " / ".join(line.strip() for line in text.splitlines() if line.strip())
    if len(text) > MAX_TEXT_LENGTH:
        text = text[: MAX_TEXT_LENGTH - 3] + "..."
    return text


def render_count(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def render_metadata(metadata: FunctionMetadata) -> list[str]:
    lines = []
    if metadata.prototype:
        lines.append(f"  type: {render_text(metadata.prototype)}")
    if metadata.function_comment:
        lines.append(f"  comment: {render_text(metadata.function_comment)}")
    if metadata.repeatable_function_comment:
        lines.append(
            f"  repeatable comment: {render_text(metadata.repeatable_function_comment)}"
        )

    if metadata.frame_members:
        members = []
        for m in metadata.frame_members[:MAX_FRAME_MEMBERS]:
            member = m.name or f"0x{m.offset:X}"
            if m.comment:
                member += f' "{render_text(m.comment)}"'
            members.append(member)
        if len(metadata.frame_members) > MAX_FRAME_MEMBERS:
            members.append(
                f"and {len(metadata.frame_members) - MAX_FRAME_MEMBERS} more"
            )
        lines.append(f"  frame: {', '.join(members)}")

    counts = []
    if metadata.instruction_comments:
        counts.append(
            render_count(len(metadata.instruction_comments), "instruction comment")
        )
    if metadata.extra_comments:
        counts.append(render_count(len(metadata.extra_comments), "extra comment"))
    if metadata.operand_representation_count:
        counts.append(
            render_count(
                metadata.operand_representation_count, "operand representation"
            )
        )
    if metadata.user_stack_point_count:
        counts.append(render_count(metadata.user_stack_point_count, "user stack point"))
    if counts:
        lines.append(f"  {', '.join(counts)}")

    return lines


def render_history_entry(entry: HistoryEntry) -> str:
    return f"    {entry.timestamp:%Y-%m-%d %H:%M} {render_text(entry.name)}"


def render_history(history: list[HistoryEntry]) -> list[str]:
    if not history:
        return []
    lines = [f"  history: {render_count(len(history), 'version')}, newest first"]
    lines.extend(render_history_entry(e) for e in history[:MAX_HISTORY_ENTRIES])
    if len(history) > MAX_HISTORY_ENTRIES:
        lines.append(
            f"    and {render_count(len(history) - MAX_HISTORY_ENTRIES, 'older version')}"
        )
    return lines


def render_record(record: LuminaRecord, local_name: str) -> list[str]:
    header = f"{COMMENT_HEADER_PREFIX}{record.server}: {record.name}"
    if record.name != local_name:
        header += f" (local name: {local_name})"

    return [
        header,
        f"  frequency {record.frequency:,}, score {record.score}, size 0x{record.size:X}",
        *render_metadata(record.metadata),
        *render_history(record.history),
    ]


def render_function_comment(records: list[LuminaRecord], local_name: str) -> str:
    return "\n".join(
        line for record in records for line in render_record(record, local_name)
    )


def get_merged_comment(existing: str, block: str) -> str:
    """
    Replace the Lumina block at the end of an existing function comment, keeping the text above it.
    """
    lines = existing.splitlines()
    for i, line in enumerate(lines):
        if COMMENT_HEADER.match(line):
            lines = lines[:i]
            break

    kept = "\n".join(lines).rstrip()
    if not block:
        return kept
    if not kept:
        return block
    return f"{kept}\n\n{block}"


def annotate_functions(db: Database) -> dict[int, list[LuminaRecord]]:
    """
    Query Lumina for every function and update the function comments.

    Raises:
        RuntimeError: if no Lumina server is reachable, or a server returns a malformed response.
    """
    funcs = {f.start_ea: f for f in db.functions}
    func_eas = sorted(funcs)

    records: dict[int, list[LuminaRecord]] = {}
    for server, client in get_lumina_clients().items():
        logger.info(
            "querying the %s Lumina server for %d functions", server, len(func_eas)
        )
        found = get_lumina_records(client, server, func_eas)
        logger.info(
            "the %s Lumina server has records for %d functions", server, len(found)
        )
        if found:
            histories = get_func_histories(client, sorted(found))
            logger.info(
                "the %s Lumina server has history for %d functions",
                server,
                len(histories),
            )
            for ea, history in histories.items():
                if ea in found:
                    found[ea].history = history
        for ea, record in found.items():
            records.setdefault(ea, []).append(record)

    for ea in func_eas:
        func = funcs[ea]
        block = render_function_comment(
            records.get(ea, []), db.functions.get_name(func)
        )
        existing = db.functions.get_comment(func)
        merged = get_merged_comment(existing, block)
        if merged != existing:
            db.functions.set_comment(func, merged)

    return records


def output_json(records: dict[int, list[LuminaRecord]]) -> None:
    doc = {
        f"{ea:#x}": [dataclasses.asdict(r) for r in rs]
        for ea, rs in sorted(records.items())
    }
    json.dump(doc, sys.stdout, indent=2, default=datetime.isoformat)
    sys.stdout.write("\n")


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="Annotate function comments with Lumina metadata",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment variables:

LUMINA_PRIMARY        Primary Lumina server, as host:port, user@host:port, or user:pass@host:port
                      (default: the server configured in IDA's Lumina options)
LUMINA_PRIMARY_TLS    Use TLS for the primary server (YES/NO)
LUMINA_SECONDARY      Secondary Lumina server, same format as LUMINA_PRIMARY
LUMINA_SECONDARY_TLS  Use TLS for the secondary server (YES/NO)
""",
    )
    parser.add_argument("input", type=Path, help="input file or IDA database")
    parser.add_argument(
        "--json", action="store_true", help="write the Lumina records to stdout as JSON"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="enable debug logging"
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="only log errors")
    args = parser.parse_args(argv)

    from rich.console import Console
    from rich.logging import RichHandler

    level = (
        logging.DEBUG if args.verbose else logging.ERROR if args.quiet else logging.INFO
    )
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=Console(stderr=True))],
    )

    def on_crash(exctype, value, tb):
        if logger.isEnabledFor(logging.DEBUG):
            logger.error("uncaught exception", exc_info=(exctype, value, tb))
        else:
            print(f"error: {value}")

    sys.excepthook = on_crash

    with Database.open(
        str(args.input), IdaCommandOptions(auto_analysis=True), save_on_close=True
    ) as db:
        records = annotate_functions(db)

    if args.json:
        output_json(records)

    return 0


def main_ida() -> None:
    logging.basicConfig(
        level=logging.INFO, format="lumina_metadata: %(message)s", force=True
    )
    db = Database.open()
    try:
        records = annotate_functions(db)
    except RuntimeError as e:
        ida_kernwin.warning(f"lumina_metadata: {e}")
        return
    logger.info("annotated %d functions", len(records))
    ida_kernwin.refresh_idaview_anyway()


if __name__ == "__main__":
    if ida_kernwin.is_ida_library(None, 0, None):
        sys.exit(main())
    else:
        main_ida()
