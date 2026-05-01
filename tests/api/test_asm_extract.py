"""Tests for ``fantasm.api.asm_extract``."""

from __future__ import annotations

import pytest

from fantasm.api import asm_extract
from fantasm.api.asm_extract import (
    AsmSection,
    build_index,
    extract_section,
    find_line_for_target,
    parse_address,
)


SAMPLE_ASM = [
    "; Header comment\n",
    "\n",
    ".start_routine\n",
    "    LDA #$00       ;8000:\n",
    "    STA $70        ;8002:\n",
    "    JSR helper     ;8004:\n",
    "    RTS            ;8007:\n",
    "\n",
    ".helper\n",
    "    LDX #$10       ;8008:\n",
    "    DEX            ;800a:\n",
    "    BNE :8008[1]   ;800b:\n",
    "    RTS            ;800d:\n",
]


# --- parse_address ---------------------------------------------------


class TestParseAddress:
    @pytest.mark.parametrize(
        "text, expected",
        [
            ("$8000", 0x8000),
            ("&abcd", 0xABCD),
            ("0xff", 0xFF),
            ("0XFF", 0xFF),
            ("ff", 0xFF),
            ("  $1234  ", 0x1234),
        ],
    )
    def test_parses_hex(self, text: str, expected: int) -> None:
        assert parse_address(text) == expected

    @pytest.mark.parametrize("text", ["", "xyz", "0x", "abcg", "label_name"])
    def test_returns_none_for_non_hex(self, text: str) -> None:
        assert parse_address(text) is None


# --- build_index -----------------------------------------------------


class TestBuildIndex:
    def test_addr_to_line_indexes_each_address(self) -> None:
        addr_to_line, _ = build_index(SAMPLE_ASM)
        assert addr_to_line[0x8000] == 3
        assert addr_to_line[0x8002] == 4
        assert addr_to_line[0x8007] == 6
        assert addr_to_line[0x800B] == 11
        assert addr_to_line[0x800D] == 12

    def test_label_to_line_indexes_each_label(self) -> None:
        _, label_to_line = build_index(SAMPLE_ASM)
        assert label_to_line == {"start_routine": 2, "helper": 8}

    def test_runtime_addresses_are_indexed_too(self) -> None:
        addr_to_line, _ = build_index(SAMPLE_ASM)
        # ":8008[1]" appears on line 11 (the BNE) — already indexed by
        # its own ;800b: comment, but the runtime ref records the
        # 0x8008 target the *first* time it's seen, which here is
        # line 9 (the helper's LDX line is ;8008:).
        assert addr_to_line[0x8008] == 9

    def test_first_occurrence_wins(self) -> None:
        # If the same address appears twice, the first hit wins.
        duplicate_lines = [
            "    LDA #$00 ;1234:\n",
            "    NOP      ;1234:\n",
        ]
        addr_to_line, _ = build_index(duplicate_lines)
        assert addr_to_line[0x1234] == 0

    def test_empty_input(self) -> None:
        addr_to_line, label_to_line = build_index([])
        assert addr_to_line == {}
        assert label_to_line == {}


# --- find_line_for_target -------------------------------------------


class TestFindLineForTarget:
    def setup_method(self) -> None:
        self.addr, self.lbl = build_index(SAMPLE_ASM)

    def test_address_exact_match(self) -> None:
        assert find_line_for_target("$8002", self.addr, self.lbl) == 4
        assert find_line_for_target("0x8004", self.addr, self.lbl) == 5

    def test_address_nearest_below_match(self) -> None:
        # 0x8003 isn't indexed, but 0x8002 is — return that line.
        assert find_line_for_target("$8003", self.addr, self.lbl) == 4

    def test_address_below_all_indexed_returns_none(self) -> None:
        assert find_line_for_target("$0000", self.addr, self.lbl) is None

    def test_label_exact_match(self) -> None:
        assert find_line_for_target("helper", self.addr, self.lbl) == 8
        assert find_line_for_target("start_routine", self.addr, self.lbl) == 2

    def test_label_substring_unique(self) -> None:
        assert find_line_for_target("rout", self.addr, self.lbl) == 2

    def test_label_substring_ambiguous_warns_and_returns_first(self) -> None:
        # Two labels share the substring "rout_". The substring must
        # not parse as a hex address — find_line_for_target prefers
        # address lookup and won't fall through to labels otherwise.
        addr_to_line: dict[int, int] = {}
        label_to_line = {"rout_one": 10, "rout_two": 20}
        with pytest.warns(UserWarning, match="ambiguous label"):
            result = find_line_for_target(
                "rout_", addr_to_line, label_to_line
            )
        # Sorted matches; "rout_one" < "rout_two" so rout_one wins.
        assert result == 10

    def test_unknown_label_returns_none(self) -> None:
        assert find_line_for_target("nosuch", self.addr, self.lbl) is None

    def test_hex_parseable_target_does_not_fall_through_to_labels(
        self,
    ) -> None:
        # "abc" parses as 0xABC; the function only tries addresses, not
        # labels, when the target parses as hex. Pinning down the
        # original sibling behaviour.
        addr_to_line: dict[int, int] = {}
        label_to_line = {"abc_label": 7}
        assert (
            find_line_for_target("abc", addr_to_line, label_to_line) is None
        )


# --- extract_section ------------------------------------------------


class TestExtractSection:
    def test_default_window_when_no_end_target(self) -> None:
        section = extract_section(SAMPLE_ASM, "start_routine", default_window=4)
        # start_line backs up over the blank line + comment header.
        assert section.start_line == 0
        # default_window = 4 from the back-up'd start (line 0).
        assert section.end_line == min(0 + 4, len(SAMPLE_ASM))
        assert section.lines == list(SAMPLE_ASM[0:4])

    def test_address_range(self) -> None:
        section = extract_section(SAMPLE_ASM, "$8000", "$8004")
        # end_line is end_target's line + 1 (inclusive).
        assert section.lines[-1] == "    JSR helper     ;8004:\n"

    def test_unknown_start_target_raises(self) -> None:
        with pytest.raises(LookupError, match="could not find"):
            extract_section(SAMPLE_ASM, "nosuch")

    def test_unknown_end_target_raises(self) -> None:
        with pytest.raises(LookupError, match="could not find"):
            extract_section(SAMPLE_ASM, "$8000", "nosuch")

    def test_returns_dataclass(self) -> None:
        section = extract_section(SAMPLE_ASM, "$8000")
        assert isinstance(section, AsmSection)
        assert isinstance(section.lines, list)

    def test_back_up_does_not_cross_address_comment(self) -> None:
        # Construct lines where the start has an address comment two
        # lines down, and only blank/comment/label lines above.
        lines = [
            "; preamble\n",
            "\n",
            "    LDA #$00 ;9000:\n",
            "    RTS      ;9002:\n",
        ]
        section = extract_section(lines, "$9000", default_window=2)
        # Start should back up to include the preamble, then the
        # default window of 2 lines from the new start.
        assert section.start_line == 0
        assert section.end_line == 2


def test_module_dunder_all() -> None:
    # Sanity-check that the public surface listed in __all__ resolves.
    for name in asm_extract.__all__:
        assert hasattr(asm_extract, name)
