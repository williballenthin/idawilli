import io
import zipfile

import pytest
from memloader.archive import (
    ArchiveError,
    BadPassword,
    extract_member,
    get_members,
    has_zip_magic,
    select_member,
)


def make_zip(files: dict[str, bytes], dirs: tuple[str, ...] = ()) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for d in dirs:
            zf.writestr(d, b"")
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_zip_magic():
    assert has_zip_magic(make_zip({"a": b"1"}))
    assert has_zip_magic(make_zip({}))
    assert not has_zip_magic(b"MZ\x90\x00")
    assert not has_zip_magic(b"")


def test_get_members_skips_directories_and_keeps_order():
    data = make_zip({"dir/b.bin": b"bb", "a.exe": b"aaa"}, dirs=("dir/",))
    members = get_members(data)
    assert [m.name for m in members] == ["dir/b.bin", "a.exe"]
    assert [m.size for m in members] == [2, 3]
    assert not any(m.encrypted for m in members)
    assert members[0].basename == "b.bin"


def test_get_members_rejects_non_zip():
    with pytest.raises(ArchiveError):
        get_members(b"not a zip at all")


def test_select_member_by_default_path_and_basename():
    members = get_members(make_zip({"x/first.exe": b"1", "second.dll": b"2"}))
    assert select_member(members, None).name == "x/first.exe"
    assert select_member(members, "x/first.exe").name == "x/first.exe"
    assert select_member(members, "first.exe").name == "x/first.exe"
    assert select_member(members, "second.dll").name == "second.dll"
    with pytest.raises(ArchiveError):
        select_member(members, "missing")
    with pytest.raises(ArchiveError):
        select_member([], None)


def test_extract_plain_member():
    data = make_zip({"a.exe": b"payload"})
    member = select_member(get_members(data), None)
    assert extract_member(data, member, None) == b"payload"
    assert extract_member(data, member, "ignored") == b"payload"


def test_extract_encrypted_member(encrypted_zip):
    data, password = encrypted_zip
    member = select_member(get_members(data), None)
    assert member.encrypted
    assert extract_member(data, member, password) == b"secret payload"
    with pytest.raises(BadPassword):
        extract_member(data, member, "wrong")
    with pytest.raises(BadPassword):
        extract_member(data, member, None)
