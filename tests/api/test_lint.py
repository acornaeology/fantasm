"""Tests for ``fantasm.api.lint``."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fantasm.api import lint
from fantasm.api.lint import (
    address_in_ranges,
    address_ranges_from_data,
    extract_annotations,
    find_code_block_ranges,
    find_nth_occurrence,
    load_address_ranges,
    load_valid_addresses,
    offset_in_code_block,
    valid_addresses_from_data,
)


# --- extract_annotations ------------------------------------------


SAMPLE_DRIVER = '''\
import py8dis

comment(0x8005, "first instruction")
subroutine(0x8000, "init", hook=None)
subroutine(0x8050,
    "load_data",
    hook=None,
    is_entry_point=False)
label(0x8100, "data_table")
label(0x8200)
'''


class TestExtractAnnotations:
    def test_extracts_kinds(self) -> None:
        anns = extract_annotations(SAMPLE_DRIVER)
        kinds = [a["kind"] for a in anns]
        assert kinds == [
            "comment",
            "subroutine",
            "subroutine",
            "label",
            "label",
        ]

    def test_extracts_addresses(self) -> None:
        anns = extract_annotations(SAMPLE_DRIVER)
        assert [a["address"] for a in anns] == [
            0x8005, 0x8000, 0x8050, 0x8100, 0x8200,
        ]

    def test_captures_name_when_present(self) -> None:
        anns = extract_annotations(SAMPLE_DRIVER)
        names = [(a["kind"], a["name"]) for a in anns]
        assert names == [
            ("comment", None),
            ("subroutine", "init"),
            ("subroutine", "load_data"),
            ("label", "data_table"),
            ("label", None),
        ]

    def test_detects_metadata_only_subroutine(self) -> None:
        anns = extract_annotations(SAMPLE_DRIVER)
        load_data = next(a for a in anns if a["address"] == 0x8050)
        assert load_data["detail"] == "metadata_only"

    def test_normal_subroutine_is_entry_point(self) -> None:
        anns = extract_annotations(SAMPLE_DRIVER)
        init = next(a for a in anns if a["address"] == 0x8000)
        assert init["detail"] == "entry_point"

    def test_line_numbers_are_1_based(self) -> None:
        anns = extract_annotations(SAMPLE_DRIVER)
        # comment(0x8005, ...) is on line 3 (after 2 lines: import + blank).
        comment_ann = anns[0]
        assert comment_ann["line_number"] == 3


# --- valid_addresses / address_ranges ------------------------------


SAMPLE_DATA = {
    "meta": {"load_addr": 0x8000, "end_addr": 0x8100},
    "items": [
        {"addr": 0x8000, "sub_labels": {"32770": ["c8002"]}},
        {"addr": 0x8002},
        {"addr": 0x0500},  # relocated runtime addr
        {"addr": 0x0501},
    ],
    "subroutines": [
        {"addr": 0x8000},
        {"addr": 0x0d00},  # NMI region sub
    ],
    "external_labels": {"oswrch": 0xFFEE},
}


class TestValidAddressesFromData:
    def test_includes_items_subs_externals_and_rom_range(self) -> None:
        addrs = valid_addresses_from_data(SAMPLE_DATA)
        assert 0x8000 in addrs
        assert 0x8050 in addrs  # ROM-range fill
        assert 0xFFEE in addrs  # external label
        assert 32770 in addrs  # sub_label
        assert 0x0500 in addrs  # item outside ROM


class TestAddressRangesFromData:
    def test_includes_rom_range(self) -> None:
        ranges = address_ranges_from_data(SAMPLE_DATA)
        assert (0x8000, 0x80FF) in ranges  # end_addr-1

    def test_groups_relocated_blocks(self) -> None:
        ranges = address_ranges_from_data(SAMPLE_DATA)
        # 0x0500/0x0501 cluster + 0x0d00 are far apart so end up in
        # separate blocks (gap > 256).
        cluster = next(
            r for r in ranges if r[0] == 0x0500
        )
        # block_padding = 32 by default for non-last; last_block_padding
        # = 16. Two blocks here, the second is the last.
        assert cluster[1] >= 0x0501  # padded forward

    def test_empty_items_returns_empty(self) -> None:
        ranges = address_ranges_from_data(
            {"meta": {"load_addr": 0x8000, "end_addr": 0x8100}, "items": []}
        )
        assert ranges == []

    def test_custom_rom_size_default(self) -> None:
        # When meta.end_addr is missing, rom_size_default kicks in.
        data = {
            "meta": {"load_addr": 0x8000},
            "items": [{"addr": 0x8000}],
            "subroutines": [],
        }
        ranges = address_ranges_from_data(data, rom_size_default=0x4000)
        assert ranges[0] == (0x8000, 0xBFFF)


class TestAddressInRanges:
    def test_inside(self) -> None:
        assert address_in_ranges(0x8050, [(0x8000, 0x80FF)]) is True

    def test_outside(self) -> None:
        assert address_in_ranges(0x9000, [(0x8000, 0x80FF)]) is False

    def test_inclusive_endpoints(self) -> None:
        assert address_in_ranges(0x8000, [(0x8000, 0x80FF)]) is True
        assert address_in_ranges(0x80FF, [(0x8000, 0x80FF)]) is True


# --- markdown helpers ----------------------------------------------


class TestFindCodeBlockRanges:
    def test_single_fenced_block(self) -> None:
        md = "intro\n```\ncode\n```\noutro\n"
        ranges = find_code_block_ranges(md)
        assert len(ranges) == 1
        start, end = ranges[0]
        assert md[start:start + 3] == "```"

    def test_no_blocks(self) -> None:
        assert find_code_block_ranges("just prose\nno code") == []

    def test_tilde_fences(self) -> None:
        md = "~~~\ncode\n~~~\n"
        ranges = find_code_block_ranges(md)
        assert len(ranges) == 1


class TestOffsetInCodeBlock:
    def test_inside(self) -> None:
        ranges = [(10, 30)]
        assert offset_in_code_block(20, ranges) is True

    def test_outside(self) -> None:
        ranges = [(10, 30)]
        assert offset_in_code_block(5, ranges) is False
        assert offset_in_code_block(35, ranges) is False

    def test_end_is_exclusive(self) -> None:
        # Per the function: start <= offset < end.
        assert offset_in_code_block(30, [(10, 30)]) is False


class TestFindNthOccurrence:
    def test_first_occurrence(self) -> None:
        assert find_nth_occurrence("foo bar foo baz", "foo", 0) == 0

    def test_second_occurrence(self) -> None:
        assert find_nth_occurrence("foo bar foo baz", "foo", 1) == 8

    def test_missing_returns_negative(self) -> None:
        assert find_nth_occurrence("foo bar", "foo", 1) == -1

    def test_pattern_absent(self) -> None:
        assert find_nth_occurrence("nothing here", "foo", 0) == -1


# --- file-IO wrappers ---------------------------------------------


class TestFileWrappers:
    def test_load_valid_addresses(self, tmp_path: Path) -> None:
        json_filepath = tmp_path / "out.json"
        json_filepath.write_text(json.dumps(SAMPLE_DATA))
        addrs = load_valid_addresses(json_filepath)
        assert 0x8000 in addrs
        assert 0xFFEE in addrs

    def test_load_address_ranges(self, tmp_path: Path) -> None:
        json_filepath = tmp_path / "out.json"
        json_filepath.write_text(json.dumps(SAMPLE_DATA))
        ranges = load_address_ranges(json_filepath)
        assert any(0x8000 <= start for start, _ in ranges)


def test_module_dunder_all_resolves() -> None:
    for name in lint.__all__:
        assert hasattr(lint, name)
