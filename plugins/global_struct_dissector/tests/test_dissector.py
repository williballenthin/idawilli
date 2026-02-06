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
            import ida_nalt
            import ida_auto

            sys.path.insert(0, "{PLUGIN_DIR}")
            from global_struct_dissector import GlobalStructDissectorHooks

            til = ida_typeinf.get_idati()

            udt = ida_typeinf.udt_type_data_t()
            udt.add_member("field_a", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32))
            udt.add_member("field_b", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32))
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

            result = ida_lines.generate_disassembly(data_ea, 30, [], [], False)
            _, tagged_lines = result
            lines = [ida_lines.tag_remove(line) for line in tagged_lines]

            hooks.unhook()

            with open("{output_path}", "w") as f:
                json.dump(lines, f)
        """),
    )

    lines = json.loads(output_path.read_text())

    # Find the struct dissection lines (after segment header comments)
    # The dissector should produce: struct SimpleStruct { ... field_a = ... field_b = ... }
    joined = "\n".join(lines)

    assert "struct SimpleStruct {" in joined
    assert "+0x00: field_a = 0x00000000" in joined
    assert "+0x04: field_b = 0x00000000" in joined
    assert "}" in joined


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
            udt_inner = ida_typeinf.udt_type_data_t()
            udt_inner.add_member("x", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32))
            udt_inner.add_member("y", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32))
            inner_tif = ida_typeinf.tinfo_t()
            inner_tif.create_udt(udt_inner)
            inner_tif.set_named_type(til, "InnerStruct", ida_typeinf.NTF_TYPE)

            # Outer struct with nested inner
            udt_outer = ida_typeinf.udt_type_data_t()
            udt_outer.add_member("header", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32))
            inner_ref = ida_typeinf.tinfo_t()
            inner_ref.get_named_type(til, "InnerStruct")
            udt_outer.add_member("nested", inner_ref)
            udt_outer.add_member("trailer", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32))
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

            result = ida_lines.generate_disassembly(data_ea, 30, [], [], False)
            _, tagged_lines = result
            lines = [ida_lines.tag_remove(line) for line in tagged_lines]

            hooks.unhook()

            with open("{output_path}", "w") as f:
                json.dump(lines, f)
        """),
    )

    lines = json.loads(output_path.read_text())
    joined = "\n".join(lines)

    assert "struct OuterStruct {" in joined
    assert "+0x00: header = " in joined
    assert "+0x04: nested =" in joined
    assert "struct InnerStruct {" in joined
    assert "+0x00: x = " in joined
    assert "+0x04: y = " in joined
    assert "+0x0C: trailer = " in joined

    # Verify nesting: InnerStruct should appear after "nested ="
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

            udt = ida_typeinf.udt_type_data_t()
            udt.add_member("field_a", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32))
            udt.add_member("field_b", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32))
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

            result = ida_lines.generate_disassembly(data_ea, 30, [], [], False)
            _, tagged_lines = result
            lines = [ida_lines.tag_remove(line) for line in tagged_lines]

            hooks.unhook()

            with open("{output_path}", "w") as f:
                json.dump(lines, f)
        """),
    )

    lines = json.loads(output_path.read_text())
    joined = "\n".join(lines)

    # Array should show [0] and [1] markers
    assert "/* [0] */" in joined
    assert "/* [1] */" in joined

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

            udt = ida_typeinf.udt_type_data_t()
            udt.is_union = True
            udt.add_member("as_int", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32))
            udt.add_member("as_float", ida_typeinf.tinfo_t(ida_typeinf.BTF_FLOAT))
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

            result = ida_lines.generate_disassembly(data_ea, 30, [], [], False)
            _, tagged_lines = result
            lines = [ida_lines.tag_remove(line) for line in tagged_lines]

            hooks.unhook()

            with open("{output_path}", "w") as f:
                json.dump(lines, f)
        """),
    )

    lines = json.loads(output_path.read_text())
    joined = "\n".join(lines)

    assert "union TestUnion {" in joined
    assert "/* union - showing all interpretations */" in joined
    # Both members should show offset +0x00 since it's a union
    assert "+0x00: as_int = " in joined
    assert "+0x00: as_float = " in joined


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

            udt = ida_typeinf.udt_type_data_t()
            udt.add_member("value", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32))
            udt.add_member("next", ptr_tif)
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

            result = ida_lines.generate_disassembly(data_ea, 30, [], [], False)
            _, tagged_lines = result
            lines = [ida_lines.tag_remove(line) for line in tagged_lines]

            hooks.unhook()

            with open("{output_path}", "w") as f:
                json.dump(lines, f)
        """),
    )

    lines = json.loads(output_path.read_text())
    joined = "\n".join(lines)

    assert "struct PtrStruct {" in joined
    assert "+0x00: value = " in joined
    # Pointer field should show the pointer value (rendered with 0x prefix)
    assert "+0x04: next = 0x" in joined


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
            result = ida_lines.generate_disassembly(code_ea, 30, [], [], False)
            _, tagged_lines = result
            lines = [ida_lines.tag_remove(line) for line in tagged_lines]

            hooks.unhook()

            with open("{output_path}", "w") as f:
                json.dump(lines, f)
        """),
    )

    lines = json.loads(output_path.read_text())
    joined = "\n".join(lines)

    # Code segment lines should NOT have struct dissection
    assert "struct" not in joined.lower() or "struct " not in joined
    # Should have typical code segment content
    assert ".text:" in joined


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
            result = ida_lines.generate_disassembly(data_ea, 30, [], [], False)
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
    joined = "\n".join(lines)

    assert not has_type
    # Without a struct type, should show raw data (db/dd), not struct dissection
    assert "+0x00:" not in joined


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
            import ida_bytes

            sys.path.insert(0, "{PLUGIN_DIR}")
            from global_struct_dissector import GlobalStructDissectorHooks

            til = ida_typeinf.get_idati()

            udt = ida_typeinf.udt_type_data_t()
            udt.add_member("ch", ida_typeinf.tinfo_t(ida_typeinf.BTF_CHAR))
            udt.add_member("value", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32))
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

            result = ida_lines.generate_disassembly(data_ea, 30, [], [], False)
            _, tagged_lines = result
            lines = [ida_lines.tag_remove(line) for line in tagged_lines]

            hooks.unhook()

            with open("{output_path}", "w") as f:
                json.dump(lines, f)
        """),
    )

    lines = json.loads(output_path.read_text())
    joined = "\n".join(lines)

    assert "struct CharStruct {" in joined
    assert "+0x00: ch = 0x00" in joined
    assert "+0x04: value = " in joined


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

            udt = ida_typeinf.udt_type_data_t()
            udt.add_member("header", ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32))
            udt.add_member("values", arr_tif)
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

            result = ida_lines.generate_disassembly(data_ea, 30, [], [], False)
            _, tagged_lines = result
            lines = [ida_lines.tag_remove(line) for line in tagged_lines]

            hooks.unhook()

            with open("{output_path}", "w") as f:
                json.dump(lines, f)
        """),
    )

    lines = json.loads(output_path.read_text())
    joined = "\n".join(lines)

    assert "struct ArrayIntStruct {" in joined
    assert "+0x00: header = " in joined
    # Array elements should be shown with indices
    assert "values[0]" in joined
    assert "values[1]" in joined
    assert "values[2]" in joined
