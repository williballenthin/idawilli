from flirt_data_pack.apply import (
    AUTO_APPLY,
    F_ELF,
    F_MACHO,
    F_PE,
    get_signatures_for,
    installed_name,
)
from flirt_data_pack.install import LINK_PREFIX


class TestInstalledName:
    def test_prefixes_base_name(self):
        assert installed_name("vc32rtf") == f"{LINK_PREFIX}vc32rtf"

    def test_dummy(self):
        assert installed_name("dummy") == "flirt_data_pack_dummy"


class TestGetSignaturesFor:
    def test_pe_returns_signatures(self):
        names = get_signatures_for(F_PE)
        assert len(names) >= 1
        assert all(n.startswith(LINK_PREFIX) for n in names)

    def test_elf_returns_signatures(self):
        names = get_signatures_for(F_ELF)
        assert len(names) >= 1

    def test_unknown_filetype_returns_empty(self):
        assert get_signatures_for(9999) == []

    def test_macho_not_mapped(self):
        if F_MACHO not in AUTO_APPLY:
            assert get_signatures_for(F_MACHO) == []

    def test_returned_names_are_prefixed(self):
        for filetype, bases in AUTO_APPLY.items():
            names = get_signatures_for(filetype)
            assert len(names) == len(bases)
            for name, base in zip(names, bases):
                assert name == f"{LINK_PREFIX}{base}"
