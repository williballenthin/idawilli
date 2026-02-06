import json
import textwrap
from pathlib import Path

from conftest import run_ida_script

PLUGIN_DIR = Path(__file__).parent.parent


def test_simple_struct(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test dissection of a simple two-field struct in a data segment."""
    output_path = work_dir / "lines.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import sys
            import json
            import ida_typeinf
            import ida_lines
            import ida_auto

            sys.path.insert(0, "{PLUGIN_DIR}")
            from global_struct_dissector import GlobalStructDissectorHooks

            til = ida_typeinf.get_idati()

            udt = build_udt([
                ("field_a", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)),
                ("field_b", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)),
            ])
            tif = ida_typeinf.tinfo_t()
            tif.create_udt(udt)
            tif.set_named_type(til, "SimpleStruct", ida_typeinf.NTF_TYPE)

            data_ea = 0x403000
            struct_tif = ida_typeinf.tinfo_t()
            struct_tif.get_named_type(til, "SimpleStruct")
            ida_typeinf.apply_tinfo(data_ea, struct_tif, ida_typeinf.TINFO_DEFINITE)

            hooks = GlobalStructDissectorHooks()
            hooks.hook()
            ida_auto.auto_wait()

            result = ida_lines.generate_disassembly(data_ea, 30, False, False)
            _, tagged_lines = result
            lines = [ida_lines.tag_remove(line) for line in tagged_lines]

            hooks.unhook()

            with open("{output_path}", "w") as f:
                json.dump(lines, f)
        """),
    )

    lines = json.loads(output_path.read_text())

    assert any("struct SimpleStruct {" in l for l in lines)
    assert ".data:00403000                   +0x00: field_a = 0x00000000" in lines
    assert ".data:00403000                   +0x04: field_b = 0x00000000" in lines
    assert ".data:00403000                 }" in lines


def test_nested_struct(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test dissection of a struct containing another struct as a field."""
    output_path = work_dir / "lines.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import sys
            import json
            import ida_typeinf
            import ida_lines
            import ida_auto

            sys.path.insert(0, "{PLUGIN_DIR}")
            from global_struct_dissector import GlobalStructDissectorHooks

            til = ida_typeinf.get_idati()

            # Inner struct
            udt_inner = build_udt([
                ("x", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)),
                ("y", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)),
            ])
            inner_tif = ida_typeinf.tinfo_t()
            inner_tif.create_udt(udt_inner)
            inner_tif.set_named_type(til, "InnerStruct", ida_typeinf.NTF_TYPE)

            # Outer struct with nested inner
            inner_ref = ida_typeinf.tinfo_t()
            inner_ref.get_named_type(til, "InnerStruct")
            udt_outer = build_udt([
                ("header", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)),
                ("nested", inner_ref),
                ("trailer", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)),
            ])
            outer_tif = ida_typeinf.tinfo_t()
            outer_tif.create_udt(udt_outer)
            outer_tif.set_named_type(til, "OuterStruct", ida_typeinf.NTF_TYPE)

            data_ea = 0x403010
            outer_ref = ida_typeinf.tinfo_t()
            outer_ref.get_named_type(til, "OuterStruct")
            ida_typeinf.apply_tinfo(data_ea, outer_ref, ida_typeinf.TINFO_DEFINITE)

            hooks = GlobalStructDissectorHooks()
            hooks.hook()
            ida_auto.auto_wait()

            result = ida_lines.generate_disassembly(data_ea, 30, False, False)
            _, tagged_lines = result
            lines = [ida_lines.tag_remove(line) for line in tagged_lines]

            hooks.unhook()

            with open("{output_path}", "w") as f:
                json.dump(lines, f)
        """),
    )

    lines = json.loads(output_path.read_text())

    assert any("struct OuterStruct {" in l for l in lines)
    assert ".data:00403010                   +0x00: header = 0x6E72656B" in lines
    assert ".data:00403010                   +0x04: nested =" in lines
    assert ".data:00403010                     struct InnerStruct {" in lines
    assert ".data:00403010                       +0x00: x = 0x32333165" in lines
    assert ".data:00403010                       +0x04: y = 0x6C6C642E" in lines
    assert ".data:00403010                     }" in lines
    assert ".data:00403010                   +0x0C: trailer = 0x00000000" in lines
    assert ".data:00403010                 }" in lines

    # Verify nesting order: InnerStruct should appear after "nested ="
    outer_open_idx = next(i for i, l in enumerate(lines) if "struct OuterStruct {" in l)
    nested_idx = next(i for i, l in enumerate(lines) if "+0x04: nested =" in l)
    inner_open_idx = next(i for i, l in enumerate(lines) if "struct InnerStruct {" in l)
    assert outer_open_idx < nested_idx < inner_open_idx


def test_array_of_structs(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test dissection of an array of structs."""
    output_path = work_dir / "lines.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import sys
            import json
            import ida_typeinf
            import ida_lines
            import ida_auto

            sys.path.insert(0, "{PLUGIN_DIR}")
            from global_struct_dissector import GlobalStructDissectorHooks

            til = ida_typeinf.get_idati()

            udt = build_udt([
                ("field_a", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)),
                ("field_b", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)),
            ])
            tif = ida_typeinf.tinfo_t()
            tif.create_udt(udt)
            tif.set_named_type(til, "ArrayElemStruct", ida_typeinf.NTF_TYPE)

            # Create array of 2 structs
            elem_ref = ida_typeinf.tinfo_t()
            elem_ref.get_named_type(til, "ArrayElemStruct")
            array_tif = ida_typeinf.tinfo_t()
            array_tif.create_array(elem_ref, 2)

            data_ea = 0x403030
            ida_typeinf.apply_tinfo(data_ea, array_tif, ida_typeinf.TINFO_DEFINITE)

            hooks = GlobalStructDissectorHooks()
            hooks.hook()
            ida_auto.auto_wait()

            result = ida_lines.generate_disassembly(data_ea, 30, False, False)
            _, tagged_lines = result
            lines = [ida_lines.tag_remove(line) for line in tagged_lines]

            hooks.unhook()

            with open("{output_path}", "w") as f:
                json.dump(lines, f)
        """),
    )

    lines = json.loads(output_path.read_text())
    joined = "\n".join(lines)

    # Array should show [0] and [1] markers with struct dissection
    assert any("/* [0] */" in l for l in lines)
    assert ".data:00403030                 struct ArrayElemStruct {" in lines
    assert ".data:00403030                   +0x00: field_a = 0x6578652E" in lines
    assert ".data:00403030                   +0x04: field_b = 0x00000000" in lines
    assert ".data:00403030                 /* [1] */" in lines
    assert ".data:00403030                   +0x00: field_a = 0x00002A5C" in lines
    assert ".data:00403030                   +0x04: field_b = 0x00002E2E" in lines

    # Each element should have struct dissection
    struct_count = joined.count("struct ArrayElemStruct {")
    assert struct_count == 2, f"Expected 2 struct dissections, got {struct_count}"


def test_union(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test dissection of a union type, showing all member interpretations."""
    output_path = work_dir / "lines.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import sys
            import json
            import ida_typeinf
            import ida_lines
            import ida_auto

            sys.path.insert(0, "{PLUGIN_DIR}")
            from global_struct_dissector import GlobalStructDissectorHooks

            til = ida_typeinf.get_idati()

            udt = build_udt([
                ("as_int", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)),
                ("as_float", ida_typeinf.tinfo_t(ida_typeinf.BTF_FLOAT)),
            ], is_union=True)
            union_tif = ida_typeinf.tinfo_t()
            union_tif.create_udt(udt, ida_typeinf.BTF_UNION)
            union_tif.set_named_type(til, "TestUnion", ida_typeinf.NTF_TYPE)

            data_ea = 0x403060
            union_ref = ida_typeinf.tinfo_t()
            union_ref.get_named_type(til, "TestUnion")
            ida_typeinf.apply_tinfo(data_ea, union_ref, ida_typeinf.TINFO_DEFINITE)

            hooks = GlobalStructDissectorHooks()
            hooks.hook()
            ida_auto.auto_wait()

            result = ida_lines.generate_disassembly(data_ea, 30, False, False)
            _, tagged_lines = result
            lines = [ida_lines.tag_remove(line) for line in tagged_lines]

            hooks.unhook()

            with open("{output_path}", "w") as f:
                json.dump(lines, f)
        """),
    )

    lines = json.loads(output_path.read_text())

    assert ".data:00403060                 union TestUnion {" in lines
    assert ".data:00403060                   /* union - showing all interpretations */" in lines
    # Both members should show offset +0x00 since it's a union
    assert ".data:00403060                   +0x00: as_int = 0x6E72656B" in lines
    assert ".data:00403060                   +0x00: as_float = 0x6E72656B" in lines
    assert ".data:00403060                 }" in lines


def test_struct_with_pointer(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test dissection of a struct with a pointer field."""
    output_path = work_dir / "lines.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import sys
            import json
            import ida_typeinf
            import ida_lines
            import ida_auto

            sys.path.insert(0, "{PLUGIN_DIR}")
            from global_struct_dissector import GlobalStructDissectorHooks

            til = ida_typeinf.get_idati()

            ptr_tif = ida_typeinf.tinfo_t()
            ptr_tif.create_ptr(ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32))

            udt = build_udt([
                ("value", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)),
                ("next", ptr_tif),
            ])
            struct_tif = ida_typeinf.tinfo_t()
            struct_tif.create_udt(udt)
            struct_tif.set_named_type(til, "PtrStruct", ida_typeinf.NTF_TYPE)

            data_ea = 0x403050
            ref = ida_typeinf.tinfo_t()
            ref.get_named_type(til, "PtrStruct")
            ida_typeinf.apply_tinfo(data_ea, ref, ida_typeinf.TINFO_DEFINITE)

            hooks = GlobalStructDissectorHooks()
            hooks.hook()
            ida_auto.auto_wait()

            result = ida_lines.generate_disassembly(data_ea, 30, False, False)
            _, tagged_lines = result
            lines = [ida_lines.tag_remove(line) for line in tagged_lines]

            hooks.unhook()

            with open("{output_path}", "w") as f:
                json.dump(lines, f)
        """),
    )

    lines = json.loads(output_path.read_text())

    assert ".data:00403050                 struct PtrStruct {" in lines
    assert ".data:00403050                   +0x00: value = 0x6F646E69" in lines
    # Pointer field should show the pointer value (rendered with 0x prefix)
    assert ".data:00403050                   +0x04: next = 0x735C7377" in lines
    assert ".data:00403050                 }" in lines


def test_code_segment_not_dissected(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that the dissector does not activate for code segments."""
    output_path = work_dir / "lines.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import sys
            import json
            import ida_typeinf
            import ida_lines
            import ida_auto

            sys.path.insert(0, "{PLUGIN_DIR}")
            from global_struct_dissector import GlobalStructDissectorHooks

            hooks = GlobalStructDissectorHooks()
            hooks.hook()
            ida_auto.auto_wait()

            # 0x401000 is in .text (code) segment
            code_ea = 0x401000
            result = ida_lines.generate_disassembly(code_ea, 30, False, False)
            _, tagged_lines = result
            lines = [ida_lines.tag_remove(line) for line in tagged_lines]

            hooks.unhook()

            with open("{output_path}", "w") as f:
                json.dump(lines, f)
        """),
    )

    lines = json.loads(output_path.read_text())

    # Code segment lines should NOT have struct dissection
    assert not any("+0x" in l and ": " in l and " = " in l for l in lines)
    # Should have typical code segment content
    assert any(".text:" in l for l in lines)


def test_no_type_not_dissected(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test that data without a struct type applied is not dissected."""
    output_path = work_dir / "lines.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import sys
            import json
            import ida_typeinf
            import ida_lines
            import ida_nalt
            import ida_auto

            sys.path.insert(0, "{PLUGIN_DIR}")
            from global_struct_dissector import GlobalStructDissectorHooks

            hooks = GlobalStructDissectorHooks()
            hooks.hook()
            ida_auto.auto_wait()

            # 0x403080 is in .data but has no struct type applied
            data_ea = 0x403080
            result = ida_lines.generate_disassembly(data_ea, 30, False, False)
            _, tagged_lines = result
            lines = [ida_lines.tag_remove(line) for line in tagged_lines]

            hooks.unhook()

            # Verify no type is applied here
            check_tif = ida_typeinf.tinfo_t()
            has_type = ida_nalt.get_tinfo(check_tif, data_ea)

            with open("{output_path}", "w") as f:
                json.dump({{"lines": lines, "has_type": has_type}}, f)
        """),
    )

    data = json.loads(output_path.read_text())
    lines = data["lines"]
    has_type = data["has_type"]

    assert not has_type
    # Without a struct type, should show raw data (db/dd), not struct dissection
    assert not any("+0x00:" in l for l in lines)
    # Should show raw byte data instead
    assert any("db " in l or "db," in l for l in lines)


def test_struct_with_byte_field(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test dissection of a struct with a single-byte char field shows char representation."""
    output_path = work_dir / "lines.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import sys
            import json
            import ida_typeinf
            import ida_lines
            import ida_auto

            sys.path.insert(0, "{PLUGIN_DIR}")
            from global_struct_dissector import GlobalStructDissectorHooks

            til = ida_typeinf.get_idati()

            udt = build_udt([
                ("ch", ida_typeinf.tinfo_t(ida_typeinf.BTF_CHAR)),
                ("value", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)),
            ])
            tif = ida_typeinf.tinfo_t()
            tif.create_udt(udt)
            tif.set_named_type(til, "CharStruct", ida_typeinf.NTF_TYPE)

            # Apply in .rdata where there's interesting byte data
            data_ea = 0x40206C
            ref = ida_typeinf.tinfo_t()
            ref.get_named_type(til, "CharStruct")
            ida_typeinf.apply_tinfo(data_ea, ref, ida_typeinf.TINFO_DEFINITE)

            hooks = GlobalStructDissectorHooks()
            hooks.hook()
            ida_auto.auto_wait()

            result = ida_lines.generate_disassembly(data_ea, 30, False, False)
            _, tagged_lines = result
            lines = [ida_lines.tag_remove(line) for line in tagged_lines]

            hooks.unhook()

            with open("{output_path}", "w") as f:
                json.dump(lines, f)
        """),
    )

    lines = json.loads(output_path.read_text())

    assert ".rdata:0040206C                 struct CharStruct {" in lines
    assert ".rdata:0040206C                   +0x00: ch = 0x00" in lines
    assert ".rdata:0040206C                   +0x04: value = 0xFFFFFFFF" in lines
    assert ".rdata:0040206C                 }" in lines


def test_struct_with_array_of_ints(test_binary: Path, session_idauser: Path, work_dir: Path):
    """Test dissection of a struct with an array of integers (non-struct elements)."""
    output_path = work_dir / "lines.json"

    run_ida_script(
        binary_path=test_binary,
        idauser=session_idauser,
        work_dir=work_dir,
        script=textwrap.dedent(f"""
            import sys
            import json
            import ida_typeinf
            import ida_lines
            import ida_auto

            sys.path.insert(0, "{PLUGIN_DIR}")
            from global_struct_dissector import GlobalStructDissectorHooks

            til = ida_typeinf.get_idati()

            # Create array type: int[3]
            int_tif = ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)
            arr_tif = ida_typeinf.tinfo_t()
            arr_tif.create_array(int_tif, 3)

            udt = build_udt([
                ("header", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)),
                ("values", arr_tif),
            ])
            tif = ida_typeinf.tinfo_t()
            tif.create_udt(udt)
            tif.set_named_type(til, "ArrayIntStruct", ida_typeinf.NTF_TYPE)

            data_ea = 0x403000
            ref = ida_typeinf.tinfo_t()
            ref.get_named_type(til, "ArrayIntStruct")
            ida_typeinf.apply_tinfo(data_ea, ref, ida_typeinf.TINFO_DEFINITE)

            hooks = GlobalStructDissectorHooks()
            hooks.hook()
            ida_auto.auto_wait()

            result = ida_lines.generate_disassembly(data_ea, 30, False, False)
            _, tagged_lines = result
            lines = [ida_lines.tag_remove(line) for line in tagged_lines]

            hooks.unhook()

            with open("{output_path}", "w") as f:
                json.dump(lines, f)
        """),
    )

    lines = json.loads(output_path.read_text())

    assert any("struct ArrayIntStruct {" in l for l in lines)
    assert ".data:00403000                   +0x00: header = 0x00000000" in lines
    # Array elements should be shown with indices and values
    assert ".data:00403000                   +0x04: values[0] = 0x00000000" in lines
    assert ".data:00403000                   +0x08: values[1] = 0x00000000" in lines
    assert ".data:00403000                   +0x0C: values[2] = 0x00000000" in lines
    assert ".data:00403000                 }" in lines
