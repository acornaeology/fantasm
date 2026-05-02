"""Tests for ``fantasm.api.bytes_search``."""

from __future__ import annotations

import pytest

from fantasm.api.bytes_search import (
    BytePattern,
    ByteMatch,
    find_byte_pattern,
    parse_byte_pattern,
)


# --- parse_byte_pattern -------------------------------------------


class TestParseHappyPath:
    def test_simple_three_bytes(self) -> None:
        pattern = parse_byte_pattern("4C B9 FF")
        assert pattern.bytes_ == (0x4C, 0xB9, 0xFF)
        assert pattern.wildcards == frozenset()
        assert len(pattern) == 3

    def test_no_whitespace(self) -> None:
        pattern = parse_byte_pattern("4cb9ff")
        assert pattern.bytes_ == (0x4C, 0xB9, 0xFF)

    def test_dollar_prefixes(self) -> None:
        pattern = parse_byte_pattern("$4C $B9 $FF")
        assert pattern.bytes_ == (0x4C, 0xB9, 0xFF)

    def test_zero_x_prefixes(self) -> None:
        pattern = parse_byte_pattern("0x4C 0xB9 0xFF")
        assert pattern.bytes_ == (0x4C, 0xB9, 0xFF)

    def test_mixed_case(self) -> None:
        pattern = parse_byte_pattern("4c B9 fF")
        assert pattern.bytes_ == (0x4C, 0xB9, 0xFF)

    def test_mixed_styles(self) -> None:
        # Spaces, $, 0x, bare, all in one pattern.
        pattern = parse_byte_pattern("$4C 0xb9 FF")
        assert pattern.bytes_ == (0x4C, 0xB9, 0xFF)


class TestParseWildcards:
    def test_middle_wildcard(self) -> None:
        pattern = parse_byte_pattern("4C ?? FF")
        assert pattern.wildcards == frozenset({1})
        # The placeholder byte at the wildcard position is zero; callers
        # should consult `wildcards`, not `bytes_[i]` directly.
        assert pattern.bytes_[1] == 0

    def test_leading_wildcard(self) -> None:
        pattern = parse_byte_pattern("?? 4C FF")
        assert pattern.wildcards == frozenset({0})

    def test_trailing_wildcard(self) -> None:
        pattern = parse_byte_pattern("4C 4C ??")
        assert pattern.wildcards == frozenset({2})

    def test_multiple_wildcards(self) -> None:
        pattern = parse_byte_pattern("A9 ?? 8D ?? ??")
        assert pattern.wildcards == frozenset({1, 3, 4})
        assert pattern.bytes_[0] == 0xA9
        assert pattern.bytes_[2] == 0x8D

    def test_wildcard_indices_sorted(self) -> None:
        pattern = parse_byte_pattern("?? 4C ??")
        assert pattern.wildcard_indices == (0, 2)

    def test_no_whitespace_with_wildcards(self) -> None:
        pattern = parse_byte_pattern("4c??ff")
        assert pattern.bytes_[0] == 0x4C
        assert pattern.bytes_[2] == 0xFF
        assert pattern.wildcards == frozenset({1})


class TestParseErrors:
    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            parse_byte_pattern("")

    def test_whitespace_only_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            parse_byte_pattern("   ")

    def test_only_prefixes_raises(self) -> None:
        # "$$$" stripped → empty cleaned.
        with pytest.raises(ValueError, match="no token characters"):
            parse_byte_pattern("$$$")

    def test_single_question_mark_raises(self) -> None:
        with pytest.raises(ValueError, match="single '\\?'"):
            parse_byte_pattern("?")

    def test_odd_length_hex_raises(self) -> None:
        with pytest.raises(ValueError, match="odd-length"):
            parse_byte_pattern("4CF")

    def test_nibble_wildcard_rejected(self) -> None:
        with pytest.raises(ValueError, match="nibble-level"):
            parse_byte_pattern("4?")

    def test_nibble_wildcard_rejected_high(self) -> None:
        with pytest.raises(ValueError, match="nibble-level"):
            parse_byte_pattern("?A")

    def test_invalid_hex_raises(self) -> None:
        with pytest.raises(ValueError, match="invalid hex"):
            parse_byte_pattern("ZZ")

    def test_entirely_wildcards_raises(self) -> None:
        with pytest.raises(ValueError, match="entirely wildcards"):
            parse_byte_pattern("?? ?? ??")


# --- find_byte_pattern --------------------------------------------


class TestFindLiteral:
    def test_single_match(self) -> None:
        rom = bytes.fromhex("00 4C B9 FF 00 00".replace(" ", ""))
        pattern = parse_byte_pattern("4C B9 FF")
        matches = find_byte_pattern(rom, pattern, rom_base=0x8000)
        assert matches == [
            ByteMatch(address=0x8001, offset=1, captures=()),
        ]

    def test_no_match(self) -> None:
        rom = bytes.fromhex("00 00 00 00")
        pattern = parse_byte_pattern("4C B9 FF")
        assert find_byte_pattern(rom, pattern) == []

    def test_multiple_matches(self) -> None:
        rom = bytes.fromhex("60 60 60 60")
        pattern = parse_byte_pattern("60")
        matches = find_byte_pattern(rom, pattern, rom_base=0x8000)
        assert [m.offset for m in matches] == [0, 1, 2, 3]
        assert [m.address for m in matches] == [0x8000, 0x8001, 0x8002, 0x8003]

    def test_match_at_first_byte(self) -> None:
        rom = bytes.fromhex("4C B9 FF AA")
        pattern = parse_byte_pattern("4C B9 FF")
        matches = find_byte_pattern(rom, pattern, rom_base=0x8000)
        assert matches[0].offset == 0

    def test_match_at_last_position(self) -> None:
        rom = bytes.fromhex("AA AA 4C B9 FF")
        pattern = parse_byte_pattern("4C B9 FF")
        matches = find_byte_pattern(rom, pattern, rom_base=0x8000)
        assert len(matches) == 1
        assert matches[0].offset == 2

    def test_pattern_longer_than_rom_returns_empty(self) -> None:
        rom = b"\x4C\xB9"
        pattern = parse_byte_pattern("4C B9 FF")
        assert find_byte_pattern(rom, pattern) == []

    def test_overlapping_matches(self) -> None:
        # The pattern "AB AB" overlaps in "AB AB AB".
        rom = bytes.fromhex("AB AB AB")
        pattern = parse_byte_pattern("AB AB")
        matches = find_byte_pattern(rom, pattern, rom_base=0x8000)
        assert [m.offset for m in matches] == [0, 1]


class TestFindWildcards:
    def test_middle_wildcard_captures(self) -> None:
        rom = bytes.fromhex("4C B9 FF AA 4C 12 FF")
        pattern = parse_byte_pattern("4C ?? FF")
        matches = find_byte_pattern(rom, pattern, rom_base=0x8000)
        assert [m.offset for m in matches] == [0, 4]
        assert matches[0].captures == (0xB9,)
        assert matches[1].captures == (0x12,)

    def test_multiple_wildcards_capture_in_order(self) -> None:
        rom = bytes.fromhex("A9 12 8D 34 56 60")
        pattern = parse_byte_pattern("A9 ?? 8D ?? ??")
        matches = find_byte_pattern(rom, pattern, rom_base=0x8000)
        assert len(matches) == 1
        # Captures appear in pattern (i.e. ascending) order.
        assert matches[0].captures == (0x12, 0x34, 0x56)

    def test_wildcard_at_rom_edge(self) -> None:
        # Match with a trailing wildcard at the very last position of
        # the ROM — the pattern fits exactly.
        rom = bytes.fromhex("4C B9 FF")
        pattern = parse_byte_pattern("4C B9 ??")
        matches = find_byte_pattern(rom, pattern, rom_base=0x8000)
        assert len(matches) == 1
        assert matches[0].captures == (0xFF,)

    def test_pure_literal_has_no_captures(self) -> None:
        rom = bytes.fromhex("4C B9 FF")
        pattern = parse_byte_pattern("4C B9 FF")
        matches = find_byte_pattern(rom, pattern, rom_base=0x8000)
        assert matches[0].captures == ()


# --- BytePattern.matches_at ---------------------------------------


class TestMatchesAt:
    def test_offset_out_of_bounds(self) -> None:
        pattern = parse_byte_pattern("4C")
        assert pattern.matches_at(b"\x4C", -1) is False
        assert pattern.matches_at(b"\x4C", 1) is False

    def test_offset_in_bounds(self) -> None:
        pattern = parse_byte_pattern("4C")
        assert pattern.matches_at(b"\x4C", 0) is True

    def test_directly_constructed_pattern(self) -> None:
        # The dataclass is constructable without going through the
        # parser — make sure a hand-rolled BytePattern still matches.
        pattern = BytePattern(
            bytes_=(0x4C, 0x00, 0xFF),
            wildcards=frozenset({1}),
        )
        assert pattern.matches_at(b"\x4C\xB9\xFF", 0) is True
        assert pattern.matches_at(b"\x4C\xB9\xAA", 0) is False
