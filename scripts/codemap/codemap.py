#!/usr/bin/env python
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "rich",
#     "ida-domain>=0.3.5",
# ]
# ///
import sys
import logging
import argparse
import contextlib
from pathlib import Path

import rich.padding
from rich.text import Text
from rich.theme import Theme
from rich.markup import escape
from rich.console import Console
from ida_domain import Database
import ida_segment
import ida_nalt
import ida_funcs
import ida_gdl

logger = logging.getLogger("codemap")


class Renderer:
    def __init__(self, console: Console):
        self.console: Console = console
        self.indent: int = 0

    @contextlib.contextmanager
    def indenting(self):
        self.indent += 1
        try:
            yield
        finally:
            self.indent -= 1

    @staticmethod
    def markup(s: str, **kwargs) -> Text:
        escaped_args = {k: (escape(v) if isinstance(v, str) else v) for k, v in kwargs.items()}
        return Text.from_markup(s.format(**escaped_args))

    def print(self, renderable, **kwargs):
        if not kwargs:
            return self.console.print(rich.padding.Padding(renderable, (0, 0, 0, self.indent * 2)))
        assert isinstance(renderable, str)
        return self.print(self.markup(renderable, **kwargs))

    def writeln(self, s: str):
        self.print(s)

    @contextlib.contextmanager
    def section(self, name):
        if isinstance(name, str):
            self.print("[title]{name}", name=name)
        elif isinstance(name, Text):
            name = name.copy()
            name.stylize_before(self.console.get_style("title"))
            self.print(name)
        else:
            raise ValueError("unexpected section name")
        with self.indenting():
            yield


def get_import_modules() -> list[str]:
    modules = []
    for i in range(ida_nalt.get_import_module_qty()):
        name = ida_nalt.get_import_module_name(i)
        if name:
            modules.append(name)
    return modules


def is_thunk(func) -> bool:
    return bool(func.flags & ida_funcs.FUNC_THUNK)


def build_import_map() -> dict[int, tuple[str, str]]:
    imports = {}
    state = {"module": ""}

    def import_callback(ea, name, ordinal):
        if name:
            imports[ea] = (state["module"], name)
        elif ordinal:
            imports[ea] = (state["module"], f"#{ordinal}")
        return True

    for i in range(ida_nalt.get_import_module_qty()):
        state["module"] = ida_nalt.get_import_module_name(i)
        ida_nalt.enum_import_names(i, import_callback)

    return imports


def main(argv: list[str] | None = None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Inspect binaries using IDA Pro")
    parser.add_argument("input_file", type=Path, help="path to input file")
    parser.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
    parser.add_argument("-q", "--quiet", action="store_true", help="disable all output but errors")
    args = parser.parse_args(args=argv)

    logging.basicConfig()
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    elif args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    theme = Theme(
        {
            "decoration": "grey54",
            "title": "yellow",
        },
        inherit=False,
    )
    console = Console(theme=theme, markup=False, emoji=False)
    o = Renderer(console)

    logger.debug("analyzing: %s", args.input_file)

    with Database() as db:
        if not db.open(str(args.input_file)):
            logger.error("failed to open database: %s", args.input_file)
            return 1

        with o.section("meta"):
            o.writeln(f"name:   {db.module}")
            o.writeln(f"sha256: {db.sha256}")
            arch = db.architecture
            if db.bitness == 32:
                arch = f"{arch.replace('metapc', 'x86')}-32"
            elif db.bitness == 64:
                arch = f"{arch.replace('metapc', 'x86')}-64"
            o.writeln(f"arch:   {arch}")

        with o.section("modules"):
            o.writeln("(none)")

        with o.section("sections"):
            for seg in db.segments.get_all():
                perm = seg.perm
                perms = ""
                perms += "r" if perm & ida_segment.SEGPERM_READ else "-"
                perms += "w" if perm & ida_segment.SEGPERM_WRITE else "-"
                perms += "x" if perm & ida_segment.SEGPERM_EXEC else "-"
                o.writeln(f"- {hex(seg.start_ea)} {perms} {hex(seg.size())}")

        with o.section("libraries"):
            modules = get_import_modules()
            for module in modules:
                module_lower = module.lower()
                if not module_lower.endswith(".dll"):
                    module_lower += ".dll"
                o.writeln(f"- {module_lower}")
            if not modules:
                o.writeln("(none)")

        # Build function order mapping for delta calculations
        all_functions = list(db.functions.get_all())
        func_order = {f.start_ea: i for i, f in enumerate(all_functions)}

        import_map = build_import_map()

        with o.section("functions"):
            for func in all_functions:
                func_name = func.name if func.name else f"sub_{func.start_ea:x}"

                if is_thunk(func):
                    with o.section(
                        o.markup(
                            "thunk {function_name} [decoration]@ {function_address}[/]",
                            function_name=func_name,
                            function_address=hex(func.start_ea),
                        )
                    ):
                        continue

                with o.section(
                    o.markup(
                        "function {function_name} [decoration]@ {function_address}[/]",
                        function_name=func_name,
                        function_address=hex(func.start_ea),
                    )
                ):
                    func_order_idx = func_order[func.start_ea]

                    # Get callers (xrefs to this function)
                    callers = db.functions.get_callers(func)
                    for caller in callers:
                        if is_thunk(caller):
                            continue
                        caller_order_idx = func_order.get(caller.start_ea)
                        if caller_order_idx is None:
                            continue
                        delta = caller_order_idx - func_order_idx
                        direction = "↑" if delta < 0 else "↓"
                        caller_name = caller.name if caller.name else f"sub_{caller.start_ea:x}"
                        o.print(
                            "xref:    [decoration]{direction}[/] {name} [decoration]({delta:+})[/]",
                            direction=direction,
                            name=caller_name,
                            delta=delta,
                        )

                    # Calculate B/E/I stats
                    try:
                        flowchart = ida_gdl.FlowChart(func)
                        num_basic_blocks = flowchart.size
                        num_edges = sum(len(list(block.succs())) for block in flowchart)

                        num_instructions = 0
                        total_bytes = 0
                        for insn in db.functions.get_instructions(func):
                            num_instructions += 1
                            total_bytes += insn.size
                    except Exception:
                        logger.debug("failed to analyze flowchart for 0x%x", func.start_ea, exc_info=True)
                        num_basic_blocks = 0
                        num_edges = 0
                        num_instructions = 0
                        total_bytes = 0

                    o.writeln(
                        f"B/E/I:     {num_basic_blocks} / {num_edges} / {num_instructions} ({total_bytes} bytes)"
                    )

                    # Get callees (internal function calls)
                    seen_callees = set()
                    callees = db.functions.get_callees(func)
                    for callee in callees:
                        if callee.start_ea in seen_callees:
                            continue

                        # Check if callee is in our function list (not an import)
                        if callee.start_ea not in func_order:
                            continue

                        seen_callees.add(callee.start_ea)

                        callee_order_idx = func_order.get(callee.start_ea)
                        delta = callee_order_idx - func_order_idx
                        direction = "↑" if delta < 0 else "↓"
                        callee_name = callee.name if callee.name else f"sub_{callee.start_ea:x}"

                        o.print(
                            "calls:   [decoration]{direction}[/] {name} [decoration]({delta:+})[/]",
                            direction=direction,
                            name=callee_name,
                            delta=delta,
                        )

                    # Get API calls
                    seen_apis = set()
                    for insn in db.functions.get_instructions(func):
                        for target_ea in db.xrefs.calls_from_ea(insn.ea):
                            if target_ea in import_map:
                                if target_ea in seen_apis:
                                    continue
                                seen_apis.add(target_ea)
                                module_name, api_name = import_map[target_ea]
                                module_lower = module_name.lower()
                                if not module_lower.endswith(".dll"):
                                    module_lower += ".dll"
                                o.print(
                                    "api:       {name}",
                                    name=f"{module_lower}!{api_name}",
                                )

                    # Get strings referenced by this function
                    seen_strings = set()
                    for insn in db.functions.get_instructions(func):
                        for xref in db.xrefs.from_ea(insn.ea):
                            if xref.to_ea in seen_strings:
                                continue
                            try:
                                string_info = db.strings.get_at(xref.to_ea)
                                if string_info and string_info.contents:
                                    seen_strings.add(xref.to_ea)
                                    content = string_info.contents
                                    if isinstance(content, bytes):
                                        content = content.decode("utf-8", errors="replace")
                                    content = content.rstrip()
                                    o.print(
                                        'string:   [decoration]"[/]{string}[decoration]"[/]',
                                        string=content,
                                    )
                            except Exception:
                                logger.debug("failed to get string at 0x%x", xref.to_ea, exc_info=True)

                    o.print("")

    return 0


if __name__ == "__main__":
    sys.exit(main())
