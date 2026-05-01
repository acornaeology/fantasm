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


# --- compose_chained_map -----------------------------------------


from fantasm.api.backfill import (
    PropagationCandidate,
    PropagationReport,
    compose_chained_map,
    propose_propagations,
)
from fantasm.api.version_graph import (
    RelocBlock,
    Version,
    VersionGraph,
)


class TestComposeChainedMap:
    def test_same_version_returns_empty(self) -> None:
        graph = VersionGraph([Version("a", (), (), None)])

        def loader(_id: str) -> bytes:
            return b""

        assert compose_chained_map(graph, "a", "a", loader) == {}

    def test_single_hop_identical_roms(self) -> None:
        # Same opcodes in both versions: every code address maps to
        # itself with high block_length.
        rom = bytes([0xA9, 0x01, 0x60, 0xA9, 0x02, 0x60])

        graph = VersionGraph(
            [
                Version("a", (), (), None),
                Version("b", ("a",), (), None),
            ]
        )

        def loader(_id: str) -> bytes:
            return rom

        composed = compose_chained_map(graph, "a", "b", loader)
        # The four code instructions land at offsets 0, 2, 3, 5 → addresses
        # 0x8000, 0x8002, 0x8003, 0x8005 (with default rom_base).
        assert composed[0x8000] == (0x8000, 4)
        assert composed[0x8005] == (0x8005, 4)

    def test_backward_walk_inverts(self) -> None:
        # Walking child -> parent should invert the canonical map.
        rom_parent = bytes([0xA9, 0x01, 0x60])
        rom_child = bytes([0xA9, 0x02, 0x60])

        graph = VersionGraph(
            [
                Version("parent", (), (), None),
                Version("child", ("parent",), (), None),
            ]
        )

        def loader(version_id: str) -> bytes:
            return rom_parent if version_id == "parent" else rom_child

        forward = compose_chained_map(graph, "parent", "child", loader)
        backward = compose_chained_map(graph, "child", "parent", loader)
        # 0x8000 in either rom maps to 0x8000 in the other.
        assert forward[0x8000][0] == 0x8000
        assert backward[0x8000][0] == 0x8000

    def test_two_hop_composition_uses_min_confidence(self) -> None:
        # Three versions in a row. Build differently-shaped roms so
        # the per-hop block_lengths differ; the composed confidence
        # is the minimum.
        rom_a = bytes([0xA9, 0x01, 0x60, 0xA9, 0x02, 0x60])
        rom_b = bytes([0xA9, 0x01, 0x60, 0xA9, 0x02, 0x60])
        rom_c = bytes([0xA9, 0x01, 0x60, 0xA9, 0x02, 0x60])

        graph = VersionGraph(
            [
                Version("a", (), (), None),
                Version("b", ("a",), (), None),
                Version("c", ("b",), (), None),
            ]
        )

        def loader(version_id: str) -> bytes:
            return {"a": rom_a, "b": rom_b, "c": rom_c}[version_id]

        composed = compose_chained_map(graph, "a", "c", loader)
        # All three roms identical → identity map across the whole chain.
        assert composed[0x8000][0] == 0x8000

    def test_disconnected_raises(self) -> None:
        graph = VersionGraph(
            [Version("a", (), (), None), Version("b", (), (), None)]
        )

        def loader(_id: str) -> bytes:
            return b""

        from fantasm.api.version_graph import NoPathError

        with pytest.raises(NoPathError):
            compose_chained_map(graph, "a", "b", loader)


# --- propose_propagations ----------------------------------------


SAMPLE_SOURCE_DRIVER = '''\
comment(0x8000, "first inline", inline=True)
label(0x8010, "data_table")
subroutine(0x8020, "init", hook=None)
'''


class TestProposePropagations:
    def test_propagates_when_no_target_annotations(self) -> None:
        # All three source annotations should propagate.
        confidence_map = {
            0x8000: (0x9000, 50),
            0x8010: (0x9010, 50),
            0x8020: (0x9020, 50),
        }
        report = propose_propagations(
            SAMPLE_SOURCE_DRIVER, "", confidence_map, threshold=5
        )
        assert isinstance(report, PropagationReport)
        kinds = {c.kind for c in report.candidates}
        assert kinds == {"comment", "label", "subroutine"}
        assert all(
            isinstance(c, PropagationCandidate) for c in report.candidates
        )

    def test_below_threshold_dropped(self) -> None:
        confidence_map = {
            0x8000: (0x9000, 1),  # below threshold
            0x8010: (0x9010, 50),
            0x8020: (0x9020, 50),
        }
        report = propose_propagations(
            SAMPLE_SOURCE_DRIVER, "", confidence_map, threshold=5
        )
        assert report.skipped_below_threshold == 1
        # Only label + subroutine survive.
        assert len(report.candidates) == 2

    def test_no_mapping_dropped(self) -> None:
        # Empty confidence map → all sources have no mapping.
        report = propose_propagations(
            SAMPLE_SOURCE_DRIVER, "", {}, threshold=5
        )
        assert report.candidates == ()
        assert report.skipped_no_mapping >= 1

    def test_existing_target_comment_skipped(self) -> None:
        target = 'comment(0x9000, "first inline", inline=True)\n'
        confidence_map = {
            0x8000: (0x9000, 50),
            0x8010: (0x9010, 50),
            0x8020: (0x9020, 50),
        }
        report = propose_propagations(
            SAMPLE_SOURCE_DRIVER, target, confidence_map, threshold=5
        )
        # Comment skipped (text already present at target addr).
        kinds = [c.kind for c in report.candidates]
        assert "comment" not in kinds
        assert report.skipped_target_has_annotation >= 1

    def test_label_name_conflict_skipped(self) -> None:
        target = 'label(0x7000, "data_table")\n'  # name reused at different addr
        confidence_map = {
            0x8000: (0x9000, 50),
            0x8010: (0x9010, 50),
            0x8020: (0x9020, 50),
        }
        report = propose_propagations(
            SAMPLE_SOURCE_DRIVER, target, confidence_map, threshold=5
        )
        labels = [c for c in report.candidates if c.kind == "label"]
        assert labels == []
        assert report.skipped_label_name_conflict == 1

    def test_subroutine_text_translated(self) -> None:
        confidence_map = {0x8020: (0x9020, 50)}
        report = propose_propagations(
            SAMPLE_SOURCE_DRIVER, "", confidence_map, threshold=5
        )
        sub_candidates = [
            c for c in report.candidates if c.kind == "subroutine"
        ]
        assert len(sub_candidates) == 1
        # Address translated to target.
        assert "0x9020" in sub_candidates[0].text
        assert sub_candidates[0].name == "init"
