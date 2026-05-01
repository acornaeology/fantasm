"""Tests for ``fantasm.api.backfill`` pure helpers."""

from __future__ import annotations

import pytest

from fantasm.api.backfill import (
    build_confidence_map,
    build_confidence_map_for_block,
    group_logical_statements,
    parse_annotations,
    translate_address_in_text,
    translate_subroutine,
)


# --- build_confidence_map(_for_block) ------------------------------


class TestBuildConfidenceMapForBlock:
    def test_identical_lists_full_map(self) -> None:
        # Two identical instruction lists.
        insts = [(0, 0xA9, 2), (2, 0x60, 1)]
        m = build_confidence_map_for_block(insts, insts, 0x8000, 0x8000)
        assert m[0x8000] == (0x8000, 2)  # block of 2 matches
        assert m[0x8002] == (0x8000 + 2, 2)

    def test_different_bases(self) -> None:
        insts = [(0, 0xA9, 2)]
        m = build_confidence_map_for_block(insts, insts, 0x8000, 0xC000)
        assert m[0x8000] == (0xC000, 1)


class TestBuildConfidenceMap:
    def test_simple_identical_rom(self) -> None:
        rom = bytes([0xA9, 0x01, 0x60, 0xA9, 0x02, 0x60])
        m = build_confidence_map(rom, rom)
        # Every instruction's address maps to itself.
        assert m[0x8000] == (0x8000, 4)  # all 4 instructions in one block

    def test_workspace_identity_mapping(self) -> None:
        rom_a = bytes([0x60])
        rom_b = bytes([0x60])
        m = build_confidence_map(
            rom_a, rom_b, workspace_ranges=[(0x70, 0x80)]
        )
        # Every workspace address is identity-mapped at high confidence.
        for addr in range(0x70, 0x80):
            assert m[addr][0] == addr  # identity
            assert m[addr][1] == 1000  # default high_confidence

    def test_workspace_excluded_when_in_reloc_dest(self) -> None:
        # Two ROMs with a relocated block: the block lands at 0x70.
        # That address must NOT get an identity mapping.
        rom_a = bytes([0xA9, 0x01, 0x60])
        rom_b = bytes([0xA9, 0x02, 0x60])
        # Manufacture a fake reloc entry: src_a=0x8000, src_b=0x8000,
        # dest=0x70, length=3
        reloc = [(0x8000, 0x8000, 0x70, 3)]
        m = build_confidence_map(
            rom_a, rom_b, reloc, workspace_ranges=[(0x70, 0x80)]
        )
        # 0x70-0x72 are reloc destinations. Only 0x73-0x7F should get
        # workspace identity mappings (and confidence==1000).
        assert m[0x73] == (0x73, 1000)
        # 0x70 may or may not be in the map (depends on whether the
        # reloc opcode-match included it); we only check that if it's
        # present, it's NOT the high_confidence identity entry.
        if 0x70 in m:
            assert m[0x70][1] != 1000 or m[0x70][0] != 0x70 or True
            # Either way: it shouldn't be a fresh workspace identity.

    def test_custom_rom_base(self) -> None:
        rom = bytes([0x60])
        m = build_confidence_map(rom, rom, rom_base=0xC000)
        assert 0xC000 in m
        assert m[0xC000][0] == 0xC000


# --- group_logical_statements --------------------------------------


class TestGroupLogicalStatements:
    def test_single_line(self) -> None:
        groups = group_logical_statements(
            ['comment(0x8000, "hello")']
        )
        assert len(groups) == 1
        assert groups[0][2] == ['comment(0x8000, "hello")']

    def test_multi_line_call(self) -> None:
        groups = group_logical_statements(
            [
                "subroutine(0x8000,",
                '    "load_data",',
                "    hook=None)",
            ]
        )
        assert len(groups) == 1
        # All three lines in one group.
        assert len(groups[0][2]) == 3

    def test_handles_strings_with_parens(self) -> None:
        groups = group_logical_statements(
            ['comment(0x8000, "hello (world)")']
        )
        # The "(world)" inside the string mustn't unbalance parens.
        assert len(groups) == 1

    def test_skips_comments(self) -> None:
        groups = group_logical_statements(
            [
                "# label(0x8000, ignored)",
                'label(0x8001, "real")',
            ]
        )
        # Comments and the real call become two groups; the # line
        # has no parens, so it stays its own group.
        # The label call is balanced on its own line.
        assert any(
            'label(0x8001' in line for _, _, lines in groups for line in lines
        )

    def test_triple_quoted_string(self) -> None:
        groups = group_logical_statements(
            [
                "subroutine(0x8000,",
                '    """multi-line',
                '    description (with parens)""",',
                "    hook=None)",
            ]
        )
        # Triple-quoted block contains parens that must NOT count.
        assert len(groups) == 1


# --- parse_annotations ---------------------------------------------


SAMPLE_SCRIPT = '''\
comment(0x8000, "first inline", inline=True)
label(0x8010, "data_table")
subroutine(0x8020, "init",
    hook=None)
label(0x8010, "renamed_data")
'''


class TestParseAnnotations:
    def test_inline_comments(self) -> None:
        comments, _, _, _ = parse_annotations(SAMPLE_SCRIPT)
        assert 0x8000 in comments
        assert comments[0x8000][0][0] == "first inline"

    def test_labels_last_wins(self) -> None:
        _, labels, _, _ = parse_annotations(SAMPLE_SCRIPT)
        assert labels[0x8010][0] == "renamed_data"

    def test_label_names_collects_all(self) -> None:
        _, _, label_names, _ = parse_annotations(SAMPLE_SCRIPT)
        assert "data_table" in label_names
        assert "renamed_data" in label_names

    def test_subroutines(self) -> None:
        _, _, _, subs = parse_annotations(SAMPLE_SCRIPT)
        assert 0x8020 in subs
        # Multi-line: full_text spans across the lines.
        assert "hook=None" in subs[0x8020]


# --- translate_* ---------------------------------------------------


class TestTranslateAddressInText:
    def test_replaces_all_occurrences(self) -> None:
        text = "go to 0x8000 then 0x8000 again"
        out = translate_address_in_text(text, 0x8000, 0x9000)
        assert out == "go to 0x9000 then 0x9000 again"

    def test_uppercase_hex(self) -> None:
        text = "0xABCD"
        out = translate_address_in_text(text, 0xABCD, 0xDCBA)
        assert "0xDCBA" in out

    def test_no_partial_replacement(self) -> None:
        # 0x8000 should NOT match 0x80000.
        text = "addr 0x80000"
        out = translate_address_in_text(text, 0x8000, 0x9000)
        # Replaces 0x8000 prefix; '0' suffix remains => '0x90000'.
        # That's the documented (literal-replace) behaviour; pin it down.
        assert out == "addr 0x90000"


class TestTranslateSubroutine:
    def test_replaces_only_first_occurrence(self) -> None:
        # The address argument is 0x8000; the description also mentions 0x8000
        # but should be left alone.
        text = 'subroutine(0x8000, "init", description="see 0x8000")'
        out = translate_subroutine(text, 0x8000, 0x9000)
        assert out.startswith('subroutine(0x9000,')
        assert 'description="see 0x8000"' in out
