#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "idapro",
#     "ida-domain",
# ]
# ///
"""
Annotate functions with what Lumina knows about them.

For each function, collect:
  - the local state: current name, Lumina pattern ID (calcrel MD5 + size),
    metadata score, whether IDA flagged the function as Lumina-provided,
    and whether a pre-Lumina backup exists (i.e., `revert` is possible);
  - one record per configured Lumina server (primary, secondary):
    name, popularity (frequency), score, and the fully decoded metadata
    (prototype, function/instruction/extra comments, frame members,
    user stack points, operand representations);
  - the diff from the local state to each Lumina record.

and render it as a function comment.

Usage, inside IDA: File > Script file... (annotates all functions;
  set LUMINA_HISTORY_EA to restrict to the current function).

Usage, headless:
  python lumina_history.py <input> [--ea 0x401000 ...] [--dry-run] [--offline-demo]

`--offline-demo` skips the network and treats the locally computed metadata
as if it were a server record, so the rendering can be inspected without
Lumina access. Its output is labeled SIMULATED.
"""

from __future__ import annotations

import argparse
import datetime
import logging
import sys
from dataclasses import dataclass, field
from typing import Any, Iterable

logger = logging.getLogger("lumina_history")

# rendered comments start with this line, so re-runs replace (not append) the block.
MARKER = "Lumina:"
MAX_FIELD_LEN = 160
MAX_FIELDS = 40
UNNAMED = "(unnamed)"


def _summary_category(topic: str, value: str | None) -> str | None:
    """
    Fields that are numerous and rarely interesting are summarized as counts:
    operand representations (offsets, enums, ...) and unnamed stack slots.
    """
    if topic.startswith("operand repr"):
        return "operand representations"
    if topic.startswith("frame +") and (value or "").startswith(UNNAMED):
        return "unnamed frame members"
    return None


@dataclass
class LuminaRecord:
    source: str
    name: str
    size: int
    score: int
    frequency: int | None = None
    # (topic, value) pairs decoded from the metadata blob
    fields: list[tuple[str, str]] = field(default_factory=list)
    # (topic, old, new) pairs: local -> this record
    diff: list[tuple[str, str, str]] = field(default_factory=list)


@dataclass
class LocalState:
    ea: int
    name: str
    size: int
    md5: str
    score: int
    is_lumina_flagged: bool
    has_backup: bool


@dataclass
class FunctionReport:
    local: LocalState
    records: list[LuminaRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _clip(s: str | None) -> str:
    if s is None:
        return "<none>"
    s = s.replace("\n", "\\n")
    if len(s) > MAX_FIELD_LEN:
        s = s[: MAX_FIELD_LEN - 3] + "..."
    return s


def _make_collector(ida_lumina, ida_typeinf, ida_bytes, ida_ida, func_ea: int):
    """
    Build a func_md_diff_handler_t that records (topic, left, right) triples.

    Diffing an empty func_info_t against a record yields every field of that record,
    so this one handler serves both for decoding and for local -> remote diffs.
    """

    class Collector(ida_lumina.func_md_diff_handler_t):
        def __init__(self):
            super().__init__()
            self.changes: list[tuple[str, str | None, str | None]] = []

        def _where(self, fchunk_nr, fchunk_off) -> str:
            site = ida_lumina.insn_site_t()
            site.fchunk_nr = fchunk_nr
            site.fchunk_off = fchunk_off
            ea = site.to_ea(func_ea)
            return f"0x{ea:X}"

        @staticmethod
        def _type(parts) -> str | None:
            if parts is None or not len(parts.type):
                return None
            tif = ida_typeinf.tinfo_t()
            if tif.deserialize(None, parts.type, parts.fields):
                return tif._print()
            return "<undecodable type>"

        def _add(self, topic, left, right):
            self.changes.append((topic, left, right))

        def on_score_changed(self, l, r):
            pass  # reported separately via score_metadata

        def on_name_changed(self, l, r):
            self._add("name", l or None, r or None)

        def on_proto_changed(self, l, r):
            self._add("prototype", self._type(l), self._type(r))

        def on_function_comment_changed(self, l, r, rep):
            self._add(
                "func cmt (repeatable)" if rep else "func cmt", l or None, r or None
            )

        def on_comment_changed(self, fchunk_nr, fchunk_off, l, r, rep):
            kind = "rpt cmt" if rep else "cmt"
            self._add(
                f"{kind} @ {self._where(fchunk_nr, fchunk_off)}", l or None, r or None
            )

        def on_extra_comment_changed(self, fchunk_nr, fchunk_off, l, r, is_prev):
            kind = "anterior" if is_prev else "posterior"
            self._add(
                f"{kind} @ {self._where(fchunk_nr, fchunk_off)}", l or None, r or None
            )

        def on_user_stkpnt_changed(self, fchunk_nr, fchunk_off, l, r):
            self._add(
                f"stkpnt @ {self._where(fchunk_nr, fchunk_off)}",
                None if l is None else str(l),
                None if r is None else str(r),
            )

        def _member(self, m) -> str | None:
            if not m:
                return None
            parts = []
            if m.name:
                parts.append(m.name)
            elif not m.cmt and not m.rptcmt:
                parts.append(UNNAMED)
            t = self._type(m.type)
            if t:
                parts.append(t)
            if m.nbytes:
                parts.append(f"{m.nbytes} bytes")
            if m.cmt:
                parts.append(f"; {m.cmt}")
            if m.rptcmt:
                parts.append(f";; {m.rptcmt}")
            if ida_bytes.is_off0(m.info.flags):
                parts.append(f"off target=0x{m.info.opinfo.ri.target:X}")
            return " ".join(parts) if parts else None

        def on_frame_member_changed(self, offset, l, r):
            self._add(f"frame +0x{offset:X}", self._member(l), self._member(r))

        def on_insn_ops_repr_changed(self, fchunk_nr, fchunk_off, l, r):
            def fmt(ro):
                if not ro:
                    return None
                ops = []
                for i in range(ida_ida.UA_MAXOP):
                    t = (ro.flags >> ida_bytes.get_operand_type_shift(i)) & 0xF
                    if t:
                        ops.append(f"op{i}=0x{t:X}")
                return ", ".join(ops) or None

            self._add(
                f"operand repr @ {self._where(fchunk_nr, fchunk_off)}", fmt(l), fmt(r)
            )

    return Collector()


class LuminaHistory:
    """Collect and render Lumina information for functions in the current database."""

    def __init__(self, offline_demo: bool = False):
        # imported lazily so that the module can be imported before idapro is bootstrapped.
        import ida_bytes
        import ida_funcs
        import ida_ida
        import ida_lumina
        import ida_name
        import ida_pro
        import ida_typeinf

        self.ida_bytes = ida_bytes
        self.ida_funcs = ida_funcs
        self.ida_ida = ida_ida
        self.ida_lumina = ida_lumina
        self.ida_name = ida_name
        self.ida_pro = ida_pro
        self.ida_typeinf = ida_typeinf
        self.offline_demo = offline_demo
        self.pulled_at = datetime.datetime.now(datetime.timezone.utc)

    def _collector(self, func_ea: int):
        return _make_collector(
            self.ida_lumina, self.ida_typeinf, self.ida_bytes, self.ida_ida, func_ea
        )

    def _diff(
        self, func_ea: int, left, right
    ) -> list[tuple[str, str | None, str | None]]:
        h = self._collector(func_ea)
        self.ida_lumina.diff_metadata(h, left, right, 0)
        return h.changes

    def local_state(self, ea: int):
        L = self.ida_lumina
        pfn = self.ida_funcs.get_func(ea)
        fi = L.func_info_t()
        # the function comment is part of the Lumina metadata, so hide our own
        # annotation while computing it, else it would leak into the local record.
        cmt = self.ida_funcs.get_func_cmt(pfn, False) or ""
        stripped = strip_block(cmt)
        if stripped != cmt:
            self.ida_funcs.set_func_cmt(pfn, stripped, False)
        try:
            res = L.calc_function_metadata(fi, pfn.start_ea)
        finally:
            if stripped != cmt:
                self.ida_funcs.set_func_cmt(pfn, cmt, False)
        # returns (size, md5 bytes) or None when the function is unsuitable (e.g., too small)
        size, md5 = res if res else (pfn.size(), b"")
        fi.name = self.ida_name.get_name(pfn.start_ea)
        local = LocalState(
            ea=pfn.start_ea,
            name=fi.name,
            size=size,
            md5=md5.hex() if md5 else "",
            score=L.score_metadata(fi),
            is_lumina_flagged=bool(pfn.flags & self.ida_funcs.FUNC_LUMINA),
            has_backup=L.has_backup_metadata(pfn.start_ea),
        )
        return local, fi

    def _record(
        self, source: str, func_ea: int, local_fi, remote_fi, frequency: int | None
    ) -> LuminaRecord:
        L = self.ida_lumina
        rec = LuminaRecord(
            source=source,
            name=remote_fi.name,
            size=remote_fi.size,
            score=L.score_metadata(remote_fi),
            frequency=frequency,
        )
        for topic, _, value in self._diff(func_ea, L.func_info_t(), remote_fi):
            if value is not None:
                rec.fields.append((topic, value))
        for topic, old, new in self._diff(func_ea, local_fi, remote_fi):
            rec.diff.append((topic, _clip(old), _clip(new)))
        return rec

    def _connections(self) -> list[tuple[str, Any]]:
        L = self.ida_lumina
        conns: list[tuple[str, Any]] = []
        for label, feature in (
            ("primary", L.LFEAT_PRIMARY_MD),
            ("secondary", L.LFEAT_SECONDARY_MD),
        ):
            try:
                c = L.get_server_connection2(feature)
            except Exception as e:  # noqa: BLE001
                logger.debug("lumina %s: %s", label, e)
                c = None
            if c:
                conns.append((label, c))
            else:
                logger.info("lumina %s: not configured or connection failed", label)
        return conns

    def collect(self, eas: Iterable[int]) -> list[FunctionReport]:
        L = self.ida_lumina
        reports: dict[int, FunctionReport] = {}
        local_fis = {}
        for ea in eas:
            local, fi = self.local_state(ea)
            reports[local.ea] = FunctionReport(local=local)
            local_fis[local.ea] = fi

        if self.offline_demo:
            for ea, rep in reports.items():
                rec = self._record(
                    "SIMULATED (local metadata)",
                    ea,
                    L.func_info_t(),
                    local_fis[ea],
                    None,
                )
                # diffing against itself would be empty; show what the record carries instead.
                rec.diff = []
                rep.records.append(rec)
            return list(reports.values())

        conns = self._connections()
        if not conns:
            for rep in reports.values():
                rep.errors.append("no Lumina server connection")
            return list(reports.values())

        ordered = sorted(reports)
        for label, conn in conns:
            eav = self.ida_pro.eavec_t()
            for ea in ordered:
                eav.push_back(ea)
            # SEEN_FILE: don't bump the server-side popularity counter just for looking.
            result = conn.pull_md(eav, L.PULL_MD_SEEN_FILE)
            codes = list(result.codes)
            results = list(result.results)
            logger.info(
                "lumina %s: %d queried, %d results", label, len(codes), len(results)
            )
            # results are returned only for inputs whose code is PDRES_OK, in input order.
            ri = 0
            for ea, code in zip(ordered, codes):
                if code != L.PDRES_OK:
                    if code != L.PDRES_NOT_FOUND:
                        reports[ea].errors.append(f"{label}: pull failed (code {code})")
                    continue
                fi = results[ri]
                ri += 1
                reports[ea].records.append(
                    self._record(label, ea, local_fis[ea], fi, fi.frequency)
                )

        return list(reports.values())


def render(rep: FunctionReport, pulled_at: datetime.datetime) -> str:
    lines = []
    lo = rep.local
    n = len(rep.records)
    lines.append(
        f"{MARKER} {n} record{'s' if n != 1 else ''} as of {pulled_at:%Y-%m-%d %H:%M}Z"
    )
    if lo.md5:
        lines.append(f"  pattern: md5:{lo.md5} ({lo.size} bytes)")
    state = []
    if lo.is_lumina_flagged:
        state.append("applied from Lumina")
    if lo.has_backup:
        state.append("pre-Lumina backup present")
    lines.append(
        f"  local:   {lo.name}  score={lo.score}"
        + (f"  [{', '.join(state)}]" if state else "")
    )

    for rec in rep.records:
        freq = f"  seen={rec.frequency}" if rec.frequency is not None else ""
        lines.append(
            f"  {rec.source}: {rec.name}{freq}  score={rec.score}  size={rec.size}"
        )
        fields = []
        summarized: dict[str, int] = {}
        for topic, value in rec.fields:
            if topic == "name":
                continue
            cat = _summary_category(topic, value)
            if cat:
                summarized[cat] = summarized.get(cat, 0) + 1
            else:
                fields.append((topic, value))
        for topic, value in fields[:MAX_FIELDS]:
            lines.append(f"    {topic}: {_clip(value)}")
        if len(fields) > MAX_FIELDS:
            lines.append(f"    ... {len(fields) - MAX_FIELDS} more fields")
        for cat, count in summarized.items():
            lines.append(f"    {cat}: {count}")
        changed = [
            (topic, old, new)
            for topic, old, new in rec.diff
            if old != new
            and not (_summary_category(topic, old) and _summary_category(topic, new))
        ]
        if changed:
            lines.append("    differs from local:")
            for topic, old, new in changed[:MAX_FIELDS]:
                lines.append(f"      {topic}: {old} -> {new}")

    for err in rep.errors:
        lines.append(f"  error: {err}")
    return "\n".join(lines)


def strip_block(cmt: str) -> str:
    """Remove a previously rendered block (if any), preserving the user's own comment text."""
    if cmt.startswith(MARKER):
        return ""
    idx = cmt.find("\n" + MARKER)
    return cmt if idx == -1 else cmt[:idx]


def merge_comment(existing: str, block: str) -> str:
    existing = strip_block(existing)
    return f"{existing}\n{block}" if existing else block


def annotate(
    db,
    eas: Iterable[int] | None = None,
    offline_demo: bool = False,
    dry_run: bool = False,
) -> list[FunctionReport]:
    """Annotate functions in an open ida_domain Database."""
    if eas is None:
        eas = [f.start_ea for f in db.functions]
    lh = LuminaHistory(offline_demo=offline_demo)
    reports = lh.collect(eas)
    for rep in reports:
        block = render(rep, lh.pulled_at)
        if not rep.records and not rep.errors:
            continue
        if dry_run:
            print(f"0x{rep.local.ea:X}:")
            print(block)
            print()
            continue
        func = db.functions.get_at(rep.local.ea)
        db.functions.set_comment(
            func, merge_comment(db.functions.get_comment(func) or "", block), False
        )
    return reports


def clear(db, eas: Iterable[int] | None = None) -> int:
    """
    Remove rendered blocks, e.g., before pushing to Lumina:
    function comments are part of the pushed metadata.
    """
    n = 0
    funcs = db.functions if eas is None else [db.functions.get_at(ea) for ea in eas]
    for func in funcs:
        cmt = db.functions.get_comment(func) or ""
        stripped = strip_block(cmt)
        if stripped != cmt:
            db.functions.set_comment(func, stripped, False)
            n += 1
    return n


def _ida_main():
    """Entry point when run via File > Script file inside IDA."""
    import os

    import ida_kernwin
    from ida_domain import Database

    db = Database.open()
    eas = None
    if os.environ.get("LUMINA_HISTORY_EA"):
        f = db.functions.get_at(ida_kernwin.get_screen_ea())
        eas = [f.start_ea] if f else []
    reports = annotate(db, eas)
    n = sum(1 for r in reports if r.records)
    print(f"lumina_history: {n}/{len(reports)} functions have Lumina records")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Annotate functions with Lumina metadata"
    )
    parser.add_argument("input", help="input file or IDB")
    parser.add_argument(
        "--ea",
        action="append",
        type=lambda s: int(s, 0),
        help="function address (repeatable)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="print comments instead of saving them"
    )
    parser.add_argument(
        "--offline-demo",
        action="store_true",
        help="don't query Lumina, render local metadata",
    )
    parser.add_argument(
        "--clear", action="store_true", help="remove previously rendered comments"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    import idapro  # noqa: F401  (bootstraps idalib)
    from ida_domain import Database
    from ida_domain.database import IdaCommandOptions

    opts = IdaCommandOptions(auto_analysis=True)
    with Database.open(args.input, opts, save_on_close=not args.dry_run) as db:
        if args.clear:
            logger.info("cleared %d comments", clear(db, args.ea))
            return 0
        reports = annotate(
            db, args.ea, offline_demo=args.offline_demo, dry_run=args.dry_run
        )
    n = sum(1 for r in reports if r.records)
    logger.info("%d/%d functions have Lumina records", n, len(reports))
    return 0


if __name__ == "__main__":
    try:
        import ida_kernwin

        in_ida = ida_kernwin.is_idaq() or not sys.argv[1:]
    except ImportError:
        in_ida = False
    if in_ida:
        _ida_main()
    else:
        sys.exit(main())
