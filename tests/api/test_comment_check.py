"""Tests for ``fantasm.api.comment_check``."""

from __future__ import annotations

import pytest

from fantasm.api import comment_check
from fantasm.api.comment_check import (
    ALL_CHECKS,
    BRANCH_MNEMONICS,
    CR_ADDRESSES,
    IMM_REG_MNEMONICS,
    TUBE_REGISTERS,
    build_known_addrs,
    check_branch_target,
    check_cr_value,
    check_reg_value,
    check_stale_addr,
    check_tube_register,
    find_chains,
    find_stale_addrs,
    parse_imm_value,
    run_checks,
)


# --- parse_imm_value ----------------------------------------------


class TestParseImmValue:
    @pytest.mark.parametrize(
        "operand, expected",
        [
            ("#&7B", 0x7B),
            ("#$1C", 0x1C),
            ("#42", 42),
            ("#0", 0),
            ("#&FF", 0xFF),
        ],
    )
    def test_parses(self, operand: str, expected: int) -> None:
        assert parse_imm_value(operand) == expected

    @pytest.mark.parametrize(
        "operand", ["", "label", "&7B", "$1C", "#abc", "#&xyz"]
    )
    def test_returns_none_on_invalid(self, operand: str) -> None:
        assert parse_imm_value(operand) is None


# --- check_reg_value ----------------------------------------------


class TestCheckRegValue:
    def test_correct_value_no_finding(self) -> None:
        item = {
            "addr": 0x8000,
            "mnemonic": "lda",
            "operand": "#&7B",
            "comment_inline": "A=&7B as expected",
        }
        assert check_reg_value(item, {}) is None

    def test_wrong_value_high(self) -> None:
        item = {
            "addr": 0x8000,
            "mnemonic": "lda",
            "operand": "#&7B",
            "comment_inline": "A=&77 (was wrong)",
        }
        result = check_reg_value(item, {})
        assert result is not None
        assert result[0]["confidence"] == "HIGH"
        assert "A=&77" in result[0]["message"]
        assert "LDA #&7B" in result[0]["message"]

    def test_wrong_register_high(self) -> None:
        item = {
            "addr": 0x8000,
            "mnemonic": "lda",
            "operand": "#0",
            "comment_inline": "X=0",
        }
        result = check_reg_value(item, {})
        assert result is not None
        assert "X=" in result[0]["message"]
        assert "sets A, not X" in result[0]["message"]

    def test_decimal_form(self) -> None:
        item = {
            "addr": 0x8000,
            "mnemonic": "ldy",
            "operand": "#5",
            "comment_inline": "Y=2 entries",
        }
        result = check_reg_value(item, {})
        assert result is not None
        assert result[0]["confidence"] == "HIGH"

    def test_non_imm_mnemonic_skipped(self) -> None:
        item = {
            "addr": 0x8000,
            "mnemonic": "cmp",
            "operand": "#5",
            "comment_inline": "A=2",
        }
        # cmp/cpx/cpy excluded — comments describe comparison values.
        assert check_reg_value(item, {}) is None


# --- check_branch_target ------------------------------------------


class TestCheckBranchTarget:
    def test_phrasing_with_wrong_target_high(self) -> None:
        item = {
            "addr": 0x8000,
            "mnemonic": "bne",
            "target": 0x8050,
            "comment_inline": "branch to &8060 if zero",
        }
        result = check_branch_target(item, {})
        assert result is not None
        assert "&8060" in result[0]["message"]

    def test_correct_target_no_finding(self) -> None:
        item = {
            "addr": 0x8000,
            "mnemonic": "bne",
            "target": 0x8060,
            "comment_inline": "branch to &8060",
        }
        assert check_branch_target(item, {}) is None

    def test_no_target_skipped(self) -> None:
        item = {
            "addr": 0x8000,
            "mnemonic": "bne",
            "target": None,
            "comment_inline": "branch to &8060",
        }
        assert check_branch_target(item, {}) is None


# --- check_cr_value ------------------------------------------------


class TestCheckCrValue:
    def test_wrong_cr_register_high(self) -> None:
        item = {
            "addr": 0x8000,
            "mnemonic": "sta",
            "target": 0xFEA0,  # CR1
            "comment_inline": "CR2=&41 set",
        }
        result = check_cr_value(item, {})
        assert result is not None
        assert "CR2" in result[0]["message"]
        assert "CR1" in result[0]["message"]

    def test_wrong_value_after_lda_high(self) -> None:
        item = {
            "addr": 0x8002,
            "mnemonic": "sta",
            "target": 0xFEA0,
            "comment_inline": "CR1=&41",
        }
        prev = {"mnemonic": "lda", "operand": "#&40"}
        result = check_cr_value(item, {"prev_item": prev})
        assert result is not None
        assert "CR1=&41" in result[0]["message"]

    def test_correct_no_finding(self) -> None:
        item = {
            "addr": 0x8002,
            "mnemonic": "sta",
            "target": 0xFEA0,
            "comment_inline": "CR1=&41",
        }
        prev = {"mnemonic": "lda", "operand": "#&41"}
        assert check_cr_value(item, {"prev_item": prev}) is None


# --- check_tube_register ------------------------------------------


class TestCheckTubeRegister:
    def test_wrong_register_medium(self) -> None:
        item = {
            "addr": 0x8000,
            "target": 0xFEE2,  # R2
            "comment_inline": "read R3 status",
        }
        result = check_tube_register(item, {})
        assert result is not None
        assert result[0]["confidence"] == "MEDIUM"
        assert "R3" in result[0]["message"]
        assert "R2" in result[0]["message"]

    def test_no_target_skipped(self) -> None:
        item = {
            "addr": 0x8000,
            "target": None,
            "comment_inline": "read R3",
        }
        assert check_tube_register(item, {}) is None


# --- find_stale_addrs / check_stale_addr --------------------------


class TestStaleAddrs:
    def test_finds_unknown_addresses(self) -> None:
        text = "from &8050 to &9000"
        known = {0x8050}
        assert find_stale_addrs(text, known) == [0x9000]

    def test_returns_empty_when_all_known(self) -> None:
        text = "from &8050"
        assert find_stale_addrs(text, {0x8050}) == []

    def test_check_stale_addr_emits_medium(self) -> None:
        item = {"addr": 0x8000, "comment_inline": "calls &9999"}
        result = check_stale_addr(item, {"known_addrs": {0x8000}})
        assert result is not None
        assert result[0]["confidence"] == "MEDIUM"


# --- find_chains --------------------------------------------------


class TestFindChains:
    def test_finds_consecutive_iny(self) -> None:
        items = [
            {"addr": 0x8000, "mnemonic": "iny"},
            {"addr": 0x8001, "mnemonic": "iny"},
            {"addr": 0x8002, "mnemonic": "iny"},
        ]
        chains = find_chains(items)
        assert len(chains) == 1
        assert len(chains[0]) == 3

    def test_separates_different_mnemonics(self) -> None:
        items = [
            {"addr": 0x8000, "mnemonic": "iny"},
            {"addr": 0x8001, "mnemonic": "iny"},
            {"addr": 0x8002, "mnemonic": "inx"},
            {"addr": 0x8003, "mnemonic": "inx"},
        ]
        chains = find_chains(items)
        assert len(chains) == 2

    def test_skips_singletons(self) -> None:
        items = [
            {"addr": 0x8000, "mnemonic": "iny"},
            {"addr": 0x8001, "mnemonic": "lda"},
        ]
        assert find_chains(items) == []

    def test_requires_consecutive_addresses(self) -> None:
        items = [
            {"addr": 0x8000, "mnemonic": "iny"},
            {"addr": 0x8002, "mnemonic": "iny"},  # gap
        ]
        assert find_chains(items) == []


# --- build_known_addrs --------------------------------------------


class TestBuildKnownAddrs:
    def test_includes_items_subs_externals_constants(self) -> None:
        data = {
            "items": [{"addr": 0x8000}, {"addr": 0x8002}],
            "subroutines": [{"addr": 0x8000}],
            "external_labels": {"oswrch": 0xFFEE},
            "constants": [{"value": 0x1234}],
        }
        known = build_known_addrs(data)
        assert 0x8000 in known
        assert 0x8002 in known
        assert 0xFFEE in known
        assert 0x1234 in known

    def test_no_implicit_bbc_ranges(self) -> None:
        # The hardcoded BBC defaults from the sibling are gone —
        # callers must pass `regions` explicitly.
        data = {
            "items": [{"addr": 0x8000}],
            "subroutines": [],
        }
        known = build_known_addrs(data)
        assert 0x0050 not in known
        assert 0xFC00 not in known

    def test_regions_explicitly_extend_known_set(self) -> None:
        data = {
            "items": [{"addr": 0x8000}],
            "subroutines": [],
        }
        regions = [
            (0x0000, 0x03FF),  # zero page + OS workspace
            (0xFC00, 0xFFFF),  # hardware
        ]
        known = build_known_addrs(data, regions=regions)
        assert 0x0050 in known
        assert 0xFC00 in known
        assert 0xFFFF in known
        # The end is inclusive.
        assert 0x03FF in known
        assert 0x0400 not in known


# --- run_checks (integration) -------------------------------------


class TestRunChecks:
    def test_invalid_sub_target_raises(self) -> None:
        data = {"items": [], "subroutines": []}
        with pytest.raises(ValueError, match="invalid address"):
            run_checks(data, sub_target="not-hex")

    def test_finds_reg_value_mismatch(self) -> None:
        data = {
            "items": [
                {
                    "addr": 0x8000,
                    "type": "code",
                    "mnemonic": "lda",
                    "operand": "#&7B",
                    "comment_inline": "A=&77 wrong",
                }
            ],
            "subroutines": [],
        }
        findings = run_checks(data)
        assert any(f["check"] == "reg_value" for f in findings)

    def test_no_findings_when_clean(self) -> None:
        data = {
            "items": [
                {
                    "addr": 0x8000,
                    "type": "code",
                    "mnemonic": "lda",
                    "operand": "#&7B",
                    "comment_inline": "A=&7B",
                }
            ],
            "subroutines": [],
        }
        findings = run_checks(data)
        assert findings == []

    def test_stale_addr_uses_regions_for_known_set(self) -> None:
        # &FFEE is inside the [0xFC00, 0xFFFF] hardware range; with
        # that region passed in, no stale finding. Without it, &FFEE
        # is treated as unknown.
        data = {
            "items": [
                {
                    "addr": 0x8000,
                    "type": "code",
                    "mnemonic": "lda",
                    "operand": "#0",
                    "comment_inline": "calls &FFEE",
                }
            ],
            "subroutines": [],
        }
        with_region = run_checks(
            data, regions=[(0xFC00, 0xFFFF)]
        )
        without_region = run_checks(data)
        # No finding when region present; stale-addr finding when not.
        assert not any(f["check"] == "stale_addr" for f in with_region)
        assert any(f["check"] == "stale_addr" for f in without_region)


def test_module_dunder_all_resolves() -> None:
    for name in comment_check.__all__:
        assert hasattr(comment_check, name)


def test_constants_consistent() -> None:
    # Sanity: TUBE_REGISTERS keys are in the FEE0-FEE7 range.
    assert all(0xFEE0 <= addr <= 0xFEE7 for addr in TUBE_REGISTERS)
    # IMM_REG_MNEMONICS values are register letters.
    assert set(IMM_REG_MNEMONICS.values()) <= {"A", "X", "Y"}
    # ALL_CHECKS contains the public check functions.
    assert check_reg_value in ALL_CHECKS
    assert check_stale_addr in ALL_CHECKS
