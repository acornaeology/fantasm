"""Tests for ``fantasm.api.audit`` pure-logic helpers and data loading."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fantasm.api import audit
from fantasm.api.audit import (
    ALL_FLAGS,
    BRANCH_MNEMONICS,
    TERMINATING_MNEMONICS,
    build_memory_regions,
    end_type,
    find_containing_sub,
    find_sub,
    find_undeclared_subs,
    load_subroutines,
    region_for_addr,
    scan_routine_range,
)


# Realistic sample base regions (the BBC zero-page and NMI workspace
# from NFS). Used in tests that exercise sub-extent computation
# across non-ROM regions.
SAMPLE_BASE_REGIONS = [
    (0x0016, 0x0076),
    (0x0400, 0x04FF),
    (0x0500, 0x05FF),
    (0x0600, 0x06FF),
    (0x0D00, 0x0DFF),
]


# --- Constants ------------------------------------------------------


class TestConstants:
    def test_terminating_mnemonics(self) -> None:
        assert TERMINATING_MNEMONICS == frozenset({"rts", "jmp", "brk", "rti"})

    def test_branch_mnemonics(self) -> None:
        assert BRANCH_MNEMONICS == frozenset(
            {"bcc", "bcs", "beq", "bne", "bmi", "bpl", "bvc", "bvs"}
        )

    def test_all_flags(self) -> None:
        assert "FALL_THROUGH" in ALL_FLAGS
        assert "NO_REFS" in ALL_FLAGS
        assert "AUTO_NAME" in ALL_FLAGS


# --- build_memory_regions -------------------------------------------


class TestBuildMemoryRegions:
    def test_rom_only_default(self) -> None:
        # No base regions: just the ROM range from meta.
        meta = {"load_addr": 0x8000, "end_addr": 0xA000}
        assert build_memory_regions(meta) == [(0x8000, 0x9FFF)]

    def test_appends_rom_region_to_base(self) -> None:
        meta = {"load_addr": 0x8000, "end_addr": 0xA000}
        regions = build_memory_regions(meta, SAMPLE_BASE_REGIONS)
        assert regions[:-1] == SAMPLE_BASE_REGIONS
        assert regions[-1] == (0x8000, 0x9FFF)

    def test_missing_meta_raises(self) -> None:
        with pytest.raises(KeyError):
            build_memory_regions({})


# --- region_for_addr -----------------------------------------------


class TestRegionForAddr:
    def setup_method(self) -> None:
        # Use the BBC base regions + ROM range to exercise both
        # workspace and ROM lookups.
        self.regions = build_memory_regions(
            {"load_addr": 0x8000, "end_addr": 0xA000},
            SAMPLE_BASE_REGIONS,
        )

    @pytest.mark.parametrize(
        "addr, expected",
        [
            (0x0050, (0x0016, 0x0076)),  # zero-page workspace
            (0x0450, (0x0400, 0x04FF)),  # page 4
            (0x0D80, (0x0D00, 0x0DFF)),  # NMI
            (0x8123, (0x8000, 0x9FFF)),  # ROM
            (0x9FFF, (0x8000, 0x9FFF)),  # ROM end inclusive
            (0x0000, None),
            (0x0100, None),
            (0xA000, None),
        ],
    )
    def test_lookup(
        self, addr: int, expected: tuple[int, int] | None
    ) -> None:
        assert region_for_addr(addr, self.regions) == expected


# --- find_containing_sub -------------------------------------------


class TestFindContainingSub:
    def setup_method(self) -> None:
        self.subs = [
            {"addr": 0x8000, "name": "sub_a"},
            {"addr": 0x8100, "name": "sub_b"},
            {"addr": 0x8200, "name": "sub_c"},
        ]

    @pytest.mark.parametrize(
        "addr, expected_name",
        [
            (0x8000, "sub_a"),
            (0x8050, "sub_a"),
            (0x80FF, "sub_a"),
            (0x8100, "sub_b"),
            (0x8200, "sub_c"),
            (0x9000, "sub_c"),  # past last sub still picks last
        ],
    )
    def test_returns_last_le_addr(
        self, addr: int, expected_name: str
    ) -> None:
        result = find_containing_sub(addr, self.subs)
        assert result is not None
        assert result["name"] == expected_name

    def test_returns_none_when_below_first_sub(self) -> None:
        assert find_containing_sub(0x7FFF, self.subs) is None

    def test_empty_list(self) -> None:
        assert find_containing_sub(0x8000, []) is None


# --- scan_routine_range --------------------------------------------


class TestScanRoutineRange:
    def test_terminates_with_rts(self) -> None:
        items_by_addr = {
            0x8000: {"addr": 0x8000, "type": "code", "mnemonic": "lda"},
            0x8002: {"addr": 0x8002, "type": "code", "mnemonic": "sta"},
            0x8004: {"addr": 0x8004, "type": "code", "mnemonic": "rts"},
        }
        result = scan_routine_range(
            0x8000, items_by_addr, sorted(items_by_addr.keys())
        )
        assert result == (0x8004, 3, 0, False)

    def test_falls_through(self) -> None:
        items_by_addr = {
            0x8000: {"addr": 0x8000, "type": "code", "mnemonic": "lda"},
            0x8002: {"addr": 0x8002, "type": "code", "mnemonic": "sta"},
        }
        result = scan_routine_range(
            0x8000, items_by_addr, sorted(items_by_addr.keys())
        )
        assert result == (None, 2, 0, True)

    def test_addr_not_in_items(self) -> None:
        items_by_addr = {
            0x8000: {"addr": 0x8000, "type": "code", "mnemonic": "rts"},
        }
        result = scan_routine_range(
            0x9000, items_by_addr, sorted(items_by_addr.keys())
        )
        assert result == (None, 0, 0, True)

    def test_data_items_counted_separately(self) -> None:
        items_by_addr = {
            0x8000: {"addr": 0x8000, "type": "code", "mnemonic": "lda"},
            0x8002: {"addr": 0x8002, "type": "data"},
            0x8003: {"addr": 0x8003, "type": "code", "mnemonic": "rts"},
        }
        result = scan_routine_range(
            0x8000, items_by_addr, sorted(items_by_addr.keys())
        )
        assert result == (0x8003, 2, 1, False)

    def test_each_terminating_mnemonic(self) -> None:
        for mnemonic in TERMINATING_MNEMONICS:
            items_by_addr = {
                0x8000: {"addr": 0x8000, "type": "code", "mnemonic": mnemonic}
            }
            result = scan_routine_range(
                0x8000, items_by_addr, [0x8000]
            )
            assert result == (0x8000, 1, 0, False)


# --- end_type ------------------------------------------------------


class TestEndType:
    def test_terminates_returns_uppercase_mnemonic(self) -> None:
        assert end_type({"terminates": True, "last_mnemonic": "rts"}) == "RTS"
        assert end_type({"terminates": True, "last_mnemonic": "jmp"}) == "JMP"

    def test_falls_through_to_next_sub(self) -> None:
        assert (
            end_type(
                {
                    "terminates": False,
                    "last_mnemonic": "lda",
                    "next_sub": {"addr": 0x8100},
                }
            )
            == "FALL→"
        )

    def test_no_terminator_no_next_sub(self) -> None:
        assert (
            end_type(
                {"terminates": False, "last_mnemonic": "lda", "next_sub": None}
            )
            == "END"
        )


# --- find_sub ------------------------------------------------------


class TestFindSub:
    def setup_method(self) -> None:
        self.subs = [
            {"addr": 0x8000, "name": "init_state"},
            {"addr": 0x8100, "name": "load_data"},
            {"addr": 0x8200, "name": "save_data"},
        ]

    @pytest.mark.parametrize("text", ["8100", "$8100", "&8100", "0x8100"])
    def test_address_match(self, text: str) -> None:
        sub = find_sub(self.subs, text)
        assert sub is not None
        assert sub["addr"] == 0x8100

    def test_exact_name_match(self) -> None:
        sub = find_sub(self.subs, "init_state")
        assert sub is not None
        assert sub["addr"] == 0x8000

    def test_substring_unique(self) -> None:
        sub = find_sub(self.subs, "init")
        assert sub is not None
        assert sub["name"] == "init_state"

    def test_ambiguous_substring_warns_returns_none(self) -> None:
        with pytest.warns(UserWarning, match="ambiguous"):
            assert find_sub(self.subs, "data") is None

    def test_unknown_target_returns_none(self) -> None:
        assert find_sub(self.subs, "no_such") is None


# --- load_subroutines / find_undeclared_subs (integration) ----------


def _write_minimal_disasm(tmp_path: Path) -> Path:
    """Create a minimal disassembly JSON for integration tests."""
    data = {
        "meta": {"load_addr": 0x8000, "end_addr": 0x8100},
        "subroutines": [
            {"addr": 0x8000, "name": "alpha", "title": "Alpha"},
            {"addr": 0x8010, "name": "beta", "title": ""},
        ],
        "items": [
            {"addr": 0x8000, "type": "code", "mnemonic": "lda"},
            {"addr": 0x8002, "type": "code", "mnemonic": "rts"},
            {"addr": 0x8010, "type": "code", "mnemonic": "lda"},
            {"addr": 0x8012, "type": "code", "mnemonic": "rts"},
            # JSR to an undeclared address.
            {"addr": 0x8020, "type": "code", "mnemonic": "jsr", "target": 0x8030},
            {"addr": 0x8023, "type": "code", "mnemonic": "rts"},
            {"addr": 0x8030, "type": "code", "mnemonic": "lda"},
            {"addr": 0x8032, "type": "code", "mnemonic": "rts"},
        ],
    }
    json_filepath = tmp_path / "out.json"
    json_filepath.write_text(json.dumps(data))
    return json_filepath


class TestLoadSubroutines:
    def test_loads_and_classifies(self, tmp_path: Path) -> None:
        # Add an unreferenced sub so we can test the NO_REFS flag.
        subs = load_subroutines(_write_minimal_disasm(tmp_path))
        assert len(subs) == 2
        names = [s["name"] for s in subs]
        assert names == ["alpha", "beta"]
        # Both terminate with RTS.
        assert all(s["terminates"] for s in subs)
        # No JSR targets these subs in the fixture, so NO_REFS.
        for s in subs:
            assert "NO_REFS" in s["flags"]


class TestFindUndeclaredSubs:
    def test_finds_jsr_target_lacking_declaration(
        self, tmp_path: Path
    ) -> None:
        candidates = find_undeclared_subs(_write_minimal_disasm(tmp_path))
        assert len(candidates) == 1
        assert candidates[0]["addr"] == 0x8030
        assert candidates[0]["caller_count"] == 1


def test_module_dunder_all_resolves() -> None:
    for name in audit.__all__:
        assert hasattr(audit, name)
