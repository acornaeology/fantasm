"""Tests for ``fantasm.api.context.compute_coverage``."""

from __future__ import annotations

import pytest

from fantasm.api.context import (
    CoverageGroup,
    CoverageReport,
    compute_coverage,
)


def _data(items, subroutines=()):
    """Wrap items + subroutines into the JSON-shaped dict the api takes."""
    return {
        "meta": {"load_addr": 0x8000, "end_addr": 0x8200},
        "items": list(items),
        "subroutines": list(subroutines),
    }


def _code(addr, mnemonic="lda", *, comment=None, **extra):
    item = {"addr": addr, "type": "code", "mnemonic": mnemonic}
    if comment is not None:
        item["comment_inline"] = comment
    item.update(extra)
    return item


def _data_item(addr, **extra):
    return {"addr": addr, "type": "data", **extra}


class TestGlobalCounts:
    def test_simple_mix(self) -> None:
        # Two of four code items commented; data items are ignored.
        data = _data(
            items=[
                _code(0x8000, comment="entry"),
                _code(0x8002),
                _code(0x8004, comment=""),    # empty comment doesn't count
                _code(0x8006, comment="rts"),
                _data_item(0x8008),           # data item ignored
            ],
            subroutines=[{"addr": 0x8000, "name": "main"}],
        )

        report = compute_coverage(data)
        assert report.code_count == 4
        assert report.commented_count == 2
        assert report.subroutine_count == 1
        assert report.percentage == pytest.approx(50.0)
        assert report.groups == ()
        assert report.group_by is None

    def test_zero_code_items_does_not_divide_by_zero(self) -> None:
        report = compute_coverage(_data(items=[]))
        assert report.code_count == 0
        assert report.commented_count == 0
        assert report.percentage == 0.0

    def test_all_commented_is_one_hundred_pct(self) -> None:
        report = compute_coverage(_data(items=[
            _code(0x8000, comment="a"),
            _code(0x8002, comment="b"),
        ]))
        assert report.percentage == pytest.approx(100.0)

    def test_block_comments_do_not_count(self) -> None:
        # Only comment_inline counts; comment_above / comment_below are
        # block-level commentary, not the per-instruction density we
        # care about.
        data = _data(items=[
            _code(0x8000, comment_above="block header"),
            _code(0x8002, comment_below="block footer"),
        ])
        report = compute_coverage(data)
        assert report.commented_count == 0


class TestGroupByPage:
    def test_two_pages(self) -> None:
        data = _data(items=[
            _code(0x8000, comment="x"),
            _code(0x8002),
            _code(0x80FF, comment="y"),    # last addr on page 80
            _code(0x8100),                  # first addr on page 81
            _code(0x8120, comment="z"),
        ])

        report = compute_coverage(data, group_by="page")
        assert report.group_by == "page"
        assert len(report.groups) == 2

        page80, page81 = report.groups
        assert page80.label == "&8000-&80FF"
        assert page80.start_addr == 0x8000
        assert page80.end_addr == 0x80FF
        assert page80.code_count == 3
        assert page80.commented_count == 2
        assert page80.percentage == pytest.approx(2 / 3 * 100)

        assert page81.label == "&8100-&81FF"
        assert page81.code_count == 2
        assert page81.commented_count == 1

    def test_pages_without_code_are_omitted(self) -> None:
        # Page &8200-&82FF has no code → no group emitted.
        data = _data(items=[
            _code(0x8000),
            _code(0x8300),
        ])
        groups = compute_coverage(data, group_by="page").groups
        assert [g.label for g in groups] == ["&8000-&80FF", "&8300-&83FF"]


class TestGroupBySub:
    def test_per_sub(self) -> None:
        # audit_subs is shaped like fantasm.api.audit.load_subroutines —
        # each dict has 'addr', 'name', and an 'items' list per-sub.
        audit_subs = [
            {
                "addr": 0x8000,
                "name": "main",
                "items": [
                    _code(0x8000, comment="hello"),
                    _code(0x8002),
                    _code(0x8004, comment="world"),
                ],
            },
            {
                "addr": 0x8010,
                "name": "helper",
                "items": [
                    _code(0x8010),
                    _code(0x8012),
                ],
            },
        ]
        data = _data(
            items=[
                _code(0x8000, comment="hello"),
                _code(0x8002),
                _code(0x8004, comment="world"),
                _code(0x8010),
                _code(0x8012),
            ],
            subroutines=[{"addr": s["addr"]} for s in audit_subs],
        )

        report = compute_coverage(data, audit_subs=audit_subs, group_by="sub")
        assert report.group_by == "sub"
        assert report.subroutine_count == 2

        main, helper = report.groups
        assert main.label == "main"
        assert main.start_addr == 0x8000
        assert main.end_addr == 0x8004
        assert main.code_count == 3
        assert main.commented_count == 2

        assert helper.label == "helper"
        assert helper.code_count == 2
        assert helper.commented_count == 0
        assert helper.percentage == 0.0

    def test_subs_emit_in_address_order(self) -> None:
        # A sub list passed in reverse order still emits in start-address
        # order in the report.
        audit_subs = [
            {"addr": 0x8100, "name": "z", "items": [_code(0x8100)]},
            {"addr": 0x8000, "name": "a", "items": [_code(0x8000)]},
        ]
        data = _data(
            items=[_code(0x8000), _code(0x8100)],
            subroutines=[{"addr": 0x8000}, {"addr": 0x8100}],
        )
        groups = compute_coverage(
            data, audit_subs=audit_subs, group_by="sub"
        ).groups
        assert [g.label for g in groups] == ["a", "z"]

    def test_sub_with_no_code_items_is_a_zero_row(self) -> None:
        # A sub registered but containing only data items (or nothing)
        # gets a zero-count row rather than being silently dropped —
        # that's the kind of "this needs annotation" finding the user
        # is reaching for.
        audit_subs = [
            {
                "addr": 0x8000,
                "name": "data_only",
                "items": [_data_item(0x8000)],
            },
        ]
        data = _data(
            items=[_data_item(0x8000)],
            subroutines=[{"addr": 0x8000}],
        )
        groups = compute_coverage(
            data, audit_subs=audit_subs, group_by="sub"
        ).groups
        assert len(groups) == 1
        assert groups[0].code_count == 0
        assert groups[0].commented_count == 0
        assert groups[0].percentage == 0.0


class TestErrors:
    def test_unknown_group_by_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown group_by"):
            compute_coverage(_data(items=[]), group_by="bogus")

    def test_group_by_sub_without_audit_subs_raises(self) -> None:
        with pytest.raises(ValueError, match="requires audit_subs"):
            compute_coverage(_data(items=[]), group_by="sub")


class TestDataclassPercentage:
    def test_group_zero_code_handles_div(self) -> None:
        group = CoverageGroup(
            label="empty", start_addr=0, end_addr=0,
            code_count=0, commented_count=0,
        )
        assert group.percentage == 0.0

    def test_report_zero_code_handles_div(self) -> None:
        report = CoverageReport(
            code_count=0, commented_count=0, subroutine_count=0,
            groups=(), group_by=None,
        )
        assert report.percentage == 0.0
