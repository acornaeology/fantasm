"""Tests for ``fantasm.api.labels``."""

from __future__ import annotations

import pytest

from fantasm.api import labels
from fantasm.api.labels import (
    AUTO_LABEL_RE,
    CATEGORY_ORDER,
    build_target_refs,
    classify_labels,
    collect_auto_labels,
    collect_labels,
    find_containing_sub_for_addr,
    inbound_refs_to,
    label_inventory,
    sort_labels,
)


# --- AUTO_LABEL_RE -------------------------------------------------


class TestAutoLabelRegex:
    @pytest.mark.parametrize(
        "label, expected",
        [
            ("c1234", True),
            ("l5678", True),
            ("loop_c00ab", True),
            ("sub_cffff", True),
            # Non-auto labels:
            ("init_state", False),
            ("read_byte", False),
            ("c1234extra", False),
            ("foo_c1234", False),
            ("C1234", False),  # uppercase rejected (auto labels are lower)
            ("", False),
        ],
    )
    def test_match(self, label: str, expected: bool) -> None:
        assert bool(AUTO_LABEL_RE.match(label)) == expected


# --- collect_auto_labels -------------------------------------------


class TestCollectAutoLabels:
    def test_extracts_labels_field(self) -> None:
        items = [
            {"addr": 0x8000, "labels": ["sub_c8000"]},
            {"addr": 0x8004, "labels": ["c8004", "init_state"]},
        ]
        assert collect_auto_labels(items) == [
            ("sub_c8000", 0x8000),
            ("c8004", 0x8004),
        ]

    def test_extracts_sub_labels_field(self) -> None:
        items = [
            {
                "addr": 0x8000,
                "labels": [],
                "sub_labels": {"32770": ["c8002"]},
            },
        ]
        assert collect_auto_labels(items) == [("c8002", 32770)]

    def test_skips_non_auto_labels(self) -> None:
        items = [
            {"addr": 0x8000, "labels": ["init_state", "main_loop"]},
        ]
        assert collect_auto_labels(items) == []

    def test_empty_items(self) -> None:
        assert collect_auto_labels([]) == []


# --- build_target_refs ---------------------------------------------


class TestBuildTargetRefs:
    def test_indexes_by_target(self) -> None:
        items = [
            {"addr": 0x8000, "target": 0x8100},
            {"addr": 0x8003, "target": 0x8100},
            {"addr": 0x8006, "target": 0x8200},
        ]
        refs = build_target_refs(items)
        assert set(refs.keys()) == {0x8100, 0x8200}
        assert len(refs[0x8100]) == 2
        assert len(refs[0x8200]) == 1

    def test_skips_items_without_target(self) -> None:
        items = [
            {"addr": 0x8000, "target": None},
            {"addr": 0x8001},
        ]
        assert build_target_refs(items) == {}


# --- find_containing_sub_for_addr ----------------------------------


class TestFindContainingSubForAddr:
    def test_same_region(self) -> None:
        regions = [(0x8000, 0x9FFF)]
        subs = [
            {"addr": 0x8000, "name": "first"},
            {"addr": 0x8100, "name": "second"},
        ]
        result = find_containing_sub_for_addr(0x8050, subs, regions)
        assert result is not None
        assert result["name"] == "first"

    def test_different_region_excluded(self) -> None:
        regions = [(0x0016, 0x0076), (0x8000, 0x9FFF)]
        subs = [
            {"addr": 0x0020, "name": "zp_helper"},
            {"addr": 0x8000, "name": "rom_init"},
        ]
        # Looking for the sub containing 0x8050 should ignore the
        # zero-page sub even though its addr <= 0x8050.
        result = find_containing_sub_for_addr(0x8050, subs, regions)
        assert result is not None
        assert result["name"] == "rom_init"

    def test_no_matching_sub_returns_none(self) -> None:
        regions = [(0x8000, 0x9FFF)]
        subs = [{"addr": 0x8100, "name": "later"}]
        # 0x8000 is in the region but no sub starts at or before it.
        assert find_containing_sub_for_addr(0x8000, subs, regions) is None


# --- classify_labels -----------------------------------------------


class TestClassifyLabels:
    def test_loop_prefix_to_internal_loop(self) -> None:
        regions = [(0x8000, 0x9FFF)]
        subs = [{"addr": 0x8000, "name": "main"}]
        items = [{"addr": 0x8004, "labels": ["loop_c8004"]}]
        results = classify_labels(
            [("loop_c8004", 0x8004)], items, {}, subs, regions
        )
        assert results[0]["category"] == "internal_loop"

    def test_sub_prefix_to_subroutine(self) -> None:
        regions = [(0x8000, 0x9FFF)]
        subs = [{"addr": 0x8000, "name": "main"}]
        items = [{"addr": 0x8050, "labels": ["sub_c8050"]}]
        results = classify_labels(
            [("sub_c8050", 0x8050)], items, {}, subs, regions
        )
        assert results[0]["category"] == "subroutine"

    def test_l_prefix_to_data(self) -> None:
        regions = [(0x8000, 0x9FFF)]
        subs = [{"addr": 0x8000, "name": "main"}]
        items = [{"addr": 0x8060, "labels": ["l8060"]}]
        results = classify_labels(
            [("l8060", 0x8060)], items, {}, subs, regions
        )
        assert results[0]["category"] == "data"

    def test_c_prefix_with_jsr_xref_to_subroutine(self) -> None:
        regions = [(0x8000, 0x9FFF)]
        subs = [
            {"addr": 0x8000, "name": "main"},
            {"addr": 0x8100, "name": "other"},
        ]
        items = [
            {"addr": 0x8060, "labels": ["c8060"]},
            {"addr": 0x8120, "mnemonic": "jsr", "target": 0x8060},
        ]
        target_refs = build_target_refs(items)
        results = classify_labels(
            [("c8060", 0x8060)], items, target_refs, subs, regions
        )
        assert results[0]["category"] == "subroutine"
        assert results[0]["cross_sub_count"] == 1

    def test_c_prefix_with_cross_sub_branch_to_shared_tail(self) -> None:
        regions = [(0x8000, 0x9FFF)]
        subs = [
            {"addr": 0x8000, "name": "main"},
            {"addr": 0x8100, "name": "other"},
        ]
        items = [
            {"addr": 0x8060, "labels": ["c8060"]},
            {"addr": 0x8120, "mnemonic": "bne", "target": 0x8060},
        ]
        target_refs = build_target_refs(items)
        results = classify_labels(
            [("c8060", 0x8060)], items, target_refs, subs, regions
        )
        assert results[0]["category"] == "shared_tail"

    def test_c_prefix_with_only_same_sub_refs_to_internal_conditional(
        self,
    ) -> None:
        regions = [(0x8000, 0x9FFF)]
        subs = [{"addr": 0x8000, "name": "main"}]
        items = [
            {"addr": 0x8060, "labels": ["c8060"]},
            {"addr": 0x8020, "mnemonic": "bne", "target": 0x8060},
        ]
        target_refs = build_target_refs(items)
        results = classify_labels(
            [("c8060", 0x8060)], items, target_refs, subs, regions
        )
        assert results[0]["category"] == "internal_conditional"


# --- sort_labels ---------------------------------------------------


class TestSortLabels:
    def test_orders_by_category_then_parent_then_addr(self) -> None:
        classified = [
            {"addr": 0x8000, "category": "data", "parent_sub_addr": 0x7000},
            {"addr": 0x8050, "category": "subroutine", "parent_sub_addr": 0x7000},
            {"addr": 0x8001, "category": "data", "parent_sub_addr": 0x6000},
            {"addr": 0x8002, "category": "subroutine", "parent_sub_addr": 0x7000},
        ]
        sorted_labels = sort_labels(classified)
        # Order: subroutine, shared_tail, data, internal_loop, internal_conditional.
        # Within each: by parent_sub_addr ascending, then addr ascending.
        assert sorted_labels[0]["addr"] == 0x8002  # subroutine, p=0x7000
        assert sorted_labels[1]["addr"] == 0x8050  # subroutine, p=0x7000
        assert sorted_labels[2]["addr"] == 0x8001  # data, p=0x6000
        assert sorted_labels[3]["addr"] == 0x8000  # data, p=0x7000

    def test_unknown_category_sorts_last(self) -> None:
        classified = [
            {"addr": 0x8000, "category": "data", "parent_sub_addr": 0},
            {"addr": 0x8001, "category": "weird", "parent_sub_addr": 0},
        ]
        sorted_labels = sort_labels(classified)
        assert sorted_labels[0]["category"] == "data"
        assert sorted_labels[1]["category"] == "weird"


def test_module_dunder_all_resolves() -> None:
    for name in labels.__all__:
        assert hasattr(labels, name)


def test_category_order_has_five_categories() -> None:
    assert len(CATEGORY_ORDER) == 5
    assert "subroutine" in CATEGORY_ORDER
    assert "shared_tail" in CATEGORY_ORDER
    assert "data" in CATEGORY_ORDER
    assert "internal_loop" in CATEGORY_ORDER
    assert "internal_conditional" in CATEGORY_ORDER


# --- collect_labels (inventory source) -----------------------------


class TestCollectLabels:
    def test_driver_labels_from_items(self) -> None:
        data = {
            "items": [
                {"addr": 0x8000, "labels": ["init", "c8000"]},
                {"addr": 0x8004, "labels": []},
            ]
        }
        assert collect_labels(data) == [
            {"name": "init", "addr": 0x8000, "source": "driver"},
            {"name": "c8000", "addr": 0x8000, "source": "driver"},
        ]

    def test_driver_labels_from_sub_labels(self) -> None:
        data = {
            "items": [
                {
                    "addr": 0x8000,
                    "labels": ["entry"],
                    "sub_labels": {"32770": ["mid"]},
                }
            ]
        }
        assert collect_labels(data) == [
            {"name": "entry", "addr": 0x8000, "source": "driver"},
            {"name": "mid", "addr": 0x8002, "source": "driver"},
        ]

    def test_env_labels_tagged_source(self) -> None:
        data = {
            "items": [],
            "external_labels": {"oswrch": 0xFFEE, "osbyte": 0xFFF4},
        }
        result = collect_labels(data)
        assert {(r["name"], r["addr"], r["source"]) for r in result} == {
            ("oswrch", 0xFFEE, "env"),
            ("osbyte", 0xFFF4, "env"),
        }

    def test_handles_missing_fields(self) -> None:
        assert collect_labels({}) == []


# --- inbound_refs_to -----------------------------------------------


class TestInboundRefsTo:
    def test_code_flow_refs(self) -> None:
        items = [
            {"addr": 0x8000, "mnemonic": "jsr", "target": 0x8100},
            {"addr": 0x8100, "mnemonic": "lda"},
            {"addr": 0x8200, "mnemonic": "jmp", "target": 0x8100},
        ]
        items_by_addr = {it["addr"]: it for it in items}
        target_refs = build_target_refs(items)
        refs = inbound_refs_to(0x8100, items_by_addr, target_refs)
        assert [r["addr"] for r in refs] == [0x8000, 0x8200]
        assert [r["mnemonic"] for r in refs] == ["jsr", "jmp"]

    def test_data_refs_from_references_field(self) -> None:
        # dasmos >= 2.0 structured references (schema_version 2).
        items = [
            {"addr": 0x8000, "mnemonic": "lda"},
            {
                "addr": 0x8100,
                "mnemonic": "byte",
                "references": [{"addr": 0x8000, "kind": "direct"}],
            },
        ]
        items_by_addr = {it["addr"]: it for it in items}
        refs = inbound_refs_to(0x8100, items_by_addr, {})
        assert refs == [{"addr": 0x8000, "mnemonic": "lda"}]

    def test_data_refs_from_pre_2_0_bare_int_references(self) -> None:
        # Pre-2.0 dasmos emitted bare-int caller addresses; still read.
        items = [
            {"addr": 0x8000, "mnemonic": "lda"},
            {"addr": 0x8100, "mnemonic": "byte", "references": [0x8000]},
        ]
        items_by_addr = {it["addr"]: it for it in items}
        refs = inbound_refs_to(0x8100, items_by_addr, {})
        assert refs == [{"addr": 0x8000, "mnemonic": "lda"}]

    def test_code_flow_wins_over_data_dup(self) -> None:
        items = [
            {"addr": 0x8000, "mnemonic": "jsr", "target": 0x8100},
            {
                "addr": 0x8100,
                "mnemonic": "lda",
                "references": [{"addr": 0x8000, "kind": "direct"}],
            },
        ]
        items_by_addr = {it["addr"]: it for it in items}
        target_refs = build_target_refs(items)
        refs = inbound_refs_to(0x8100, items_by_addr, target_refs)
        assert refs == [{"addr": 0x8000, "mnemonic": "jsr"}]


# --- label_inventory -----------------------------------------------


class TestLabelInventory:
    def test_combines_driver_and_env(self) -> None:
        data = {
            "items": [
                {"addr": 0x8000, "labels": ["init"]},
                {
                    "addr": 0x8100,
                    "mnemonic": "jsr",
                    "target": 0x8000,
                    "labels": [],
                },
            ],
            "external_labels": {"oswrch": 0xFFEE},
        }
        inventory = label_inventory(data)
        by_name = {r["name"]: r for r in inventory}
        assert by_name["init"]["source"] == "driver"
        assert by_name["init"]["addr"] == 0x8000
        assert by_name["init"]["length"] == 4
        assert by_name["init"]["ref_count"] == 1
        assert by_name["oswrch"]["source"] == "env"
        assert by_name["oswrch"]["ref_count"] == 0

    def test_driver_dedupe_on_name_and_addr(self) -> None:
        # A label appearing as both an item label and a sub-label of
        # the same item should collapse to a single inventory entry.
        data = {
            "items": [
                {
                    "addr": 0x8000,
                    "labels": ["main"],
                    "sub_labels": {"32768": ["main"]},
                }
            ]
        }
        inventory = label_inventory(data)
        assert len(inventory) == 1
        assert inventory[0]["name"] == "main"
