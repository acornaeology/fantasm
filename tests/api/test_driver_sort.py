"""Tests for ``fantasm.api.driver_sort``.

Two layers of coverage live here:

1. **Classifier and sorter unit tests** — small hand-written snippets
   that pin one decision each (a sortable moves; an anchor doesn't;
   hex stays hex; multi-line statements move as a unit; ...).

2. **Semantic equivalence round-trip** — parse a fixture driver
   before and after sort, assert the multiset of recognised
   annotation tuples is unchanged. This catches accidental
   drop / dup without needing a ROM.

A separate test module covers the synthetic-ROM byte-identity
oracle (skipped when dasmos isn't importable).
"""

from __future__ import annotations

from collections import Counter

from fantasm.api.driver_sort import (
    Unit,
    build_units,
    emit_units,
    is_sorted,
    sort_driver_text,
)


# --- helpers -------------------------------------------------------


def _stmt_kinds(units: list[Unit]) -> list[str]:
    # Trailing filler (final blank/newline) is a round-trip artefact;
    # tests focus on real statement classification.
    return [u.kind for u in units if u.kind != "trailing_filler"]


def _stmt_addresses(units: list[Unit]) -> list[int | None]:
    return [u.address for u in units if u.kind != "trailing_filler"]


# --- classifier --------------------------------------------------


class TestClassifier:
    def test_label_call_with_hex_addr_is_sortable(self) -> None:
        text = 'd.label(0x9000, "foo")\n'
        units = build_units(text)
        assert _stmt_kinds(units) == ["sortable"]
        assert _stmt_addresses(units) == [0x9000]

    def test_bare_label_call_also_sortable(self) -> None:
        # py8dis-style import-* drivers omit the ``d.`` receiver.
        text = 'label(0x9000, "foo")\n'
        units = build_units(text)
        assert _stmt_kinds(units) == ["sortable"]

    def test_decimal_addr_is_accepted(self) -> None:
        text = 'd.label(36864, "foo")\n'  # 0x9000
        units = build_units(text)
        assert _stmt_kinds(units) == ["sortable"]
        assert units[0].address == 36864

    def test_non_literal_first_arg_is_anchor(self) -> None:
        # ``0x9286 + i`` is the canonical loop-emission shape and
        # must not be reordered.
        text = "d.byte(0x9286 + i)\n"
        units = build_units(text)
        assert _stmt_kinds(units) == ["anchor"]

    def test_indented_call_is_anchor(self) -> None:
        text = '    d.label(0x9000, "foo")\n'
        units = build_units(text)
        assert _stmt_kinds(units) == ["anchor"]

    def test_setup_calls_are_anchors(self) -> None:
        for setup_call in (
            "d.load(rom_filepath, 0x8000)",
            "d.add_move(0x0E00, 0xB000, 0x100)",
            "d.use_environment('acorn_mos')",
            "d.hook_subroutine(0x9261, 'print_inline', stringhi_hook)",
            "d.format_hint(0x8000, hint='code')",
            "d.constant(0x5C, 'fs_flags')",
        ):
            units = build_units(setup_call + "\n")
            assert _stmt_kinds(units) == ["anchor"], setup_call

    def test_unrecognised_call_is_anchor(self) -> None:
        text = "print('hello')\n"
        units = build_units(text)
        assert _stmt_kinds(units) == ["anchor"]

    def test_assignment_is_anchor(self) -> None:
        text = "ir = d.disassemble()\n"
        units = build_units(text)
        assert _stmt_kinds(units) == ["anchor"]

    def test_import_is_anchor(self) -> None:
        text = "import dasmos\n"
        units = build_units(text)
        assert _stmt_kinds(units) == ["anchor"]

    def test_each_sortable_kind_recognised(self) -> None:
        kinds = [
            "label",
            "comment",
            "subroutine",
            "banner",
            "entry",
            "byte",
            "word",
            "string",
            "expr",
            "expr_label",
            "rts_code_ptr",
        ]
        for kind in kinds:
            text = f"d.{kind}(0x9000)\n"
            units = build_units(text)
            assert _stmt_kinds(units) == ["sortable"], kind


# --- multi-line statements ---------------------------------------


class TestMultiLineStatements:
    def test_multiline_subroutine_moves_as_one_unit(self) -> None:
        text = (
            'd.subroutine(0xB000,\n'
            '    "foo",\n'
            '    description="""line 1\n'
            'line 2""")\n'
            'd.label(0x8000, "header")\n'
        )
        units = build_units(text)
        assert _stmt_kinds(units) == ["sortable", "sortable"]
        # Subroutine block keeps its 4 lines together.
        assert len(units[0].statement_lines) == 4
        # And it has the higher address.
        assert units[0].address == 0xB000
        assert units[1].address == 0x8000

    def test_multiline_call_address_extracted(self) -> None:
        # Address on the second physical line.
        text = (
            'd.label(\n'
            '    0xABCD,\n'
            '    "foo",\n'
            ')\n'
        )
        units = build_units(text)
        assert _stmt_kinds(units) == ["sortable"]
        assert units[0].address == 0xABCD


# --- sorting -----------------------------------------------------


class TestSortDriverText:
    def test_two_sortables_get_reordered(self) -> None:
        text = (
            'd.label(0x9000, "high")\n'
            'd.label(0x8000, "low")\n'
        )
        sorted_text = sort_driver_text(text)
        # Lower address first.
        first = sorted_text.index('d.label(0x8000')
        second = sorted_text.index('d.label(0x9000')
        assert first < second

    def test_already_sorted_is_unchanged(self) -> None:
        text = (
            'd.label(0x8000, "low")\n'
            'd.label(0x9000, "high")\n'
        )
        assert sort_driver_text(text) == text

    def test_anchor_divides_runs(self) -> None:
        # An anchor in the middle keeps the high-address run after
        # the low-address run even though it would otherwise sort
        # ahead.
        text = (
            'd.label(0xC000, "in run 1")\n'
            'd.label(0xB000, "in run 1")\n'
            "d.use_environment('acorn_mos')\n"
            'd.label(0x9000, "in run 2")\n'
            'd.label(0x8000, "in run 2")\n'
        )
        result = sort_driver_text(text)
        lines = result.splitlines()
        # Run 1 sorted: B000 then C000.
        assert lines[0] == 'd.label(0xB000, "in run 1")'
        assert lines[1] == 'd.label(0xC000, "in run 1")'
        # Anchor stays put.
        assert lines[2] == "d.use_environment('acorn_mos')"
        # Run 2 sorted: 8000 then 9000.
        assert lines[3] == 'd.label(0x8000, "in run 2")'
        assert lines[4] == 'd.label(0x9000, "in run 2")'

    def test_imports_and_setup_stay_at_top(self) -> None:
        text = (
            "import dasmos\n"
            "d = dasmos.Disassembler.create(cpu='6502')\n"
            "d.load(rom_filepath, 0x8000)\n"
            'd.label(0x9000, "high")\n'
            'd.label(0x8000, "low")\n'
        )
        result = sort_driver_text(text)
        lines = result.splitlines()
        assert lines[0] == "import dasmos"
        assert lines[1] == "d = dasmos.Disassembler.create(cpu='6502')"
        assert lines[2] == "d.load(rom_filepath, 0x8000)"
        # Sortable run begins after the prelude anchors.
        assert lines[3] == 'd.label(0x8000, "low")'
        assert lines[4] == 'd.label(0x9000, "high")'

    def test_render_coda_stays_at_bottom(self) -> None:
        text = (
            'd.label(0x9000, "high")\n'
            'd.label(0x8000, "low")\n'
            "ir = d.disassemble()\n"
            "output_filepath.write_text(str(ir.render('beebasm')))\n"
        )
        result = sort_driver_text(text)
        lines = result.splitlines()
        assert lines[0] == 'd.label(0x8000, "low")'
        assert lines[1] == 'd.label(0x9000, "high")'
        assert lines[2] == "ir = d.disassemble()"
        assert lines[3] == "output_filepath.write_text(str(ir.render('beebasm')))"

    def test_loop_body_is_not_torn_apart(self) -> None:
        text = (
            'd.label(0x9000, "before-loop")\n'
            "for i in range(3):\n"
            "    d.byte(0x8000 + i)\n"
            "    d.comment(0x8000 + i, 'in loop')\n"
            'd.label(0x9100, "after-loop")\n'
        )
        result = sort_driver_text(text)
        lines = result.splitlines()
        # The for header and its indented body keep their relative
        # order. The two outer labels are in different runs (split
        # by the loop anchor) so each run sorts independently —
        # a single element each, so no movement.
        assert lines[0] == 'd.label(0x9000, "before-loop")'
        assert lines[1] == "for i in range(3):"
        assert lines[2] == "    d.byte(0x8000 + i)"
        assert lines[3] == "    d.comment(0x8000 + i, 'in loop')"
        assert lines[4] == 'd.label(0x9100, "after-loop")'

    def test_hex_literals_preserved_verbatim(self) -> None:
        # Mix of upper and lower hex digits, with surrounding text;
        # the sort must not normalise either spelling.
        text = (
            'd.label(0xfeA0, "weird-case")\n'
            'd.label(0xBfC7, "another")\n'
        )
        result = sort_driver_text(text)
        # Both literal spellings round-trip exactly.
        assert "0xfeA0" in result
        assert "0xBfC7" in result
        # No 0x9000-style normalisation, no decimal conversion.
        assert "65184" not in result
        assert "49095" not in result

    def test_leading_comment_attaches_to_following_statement(self) -> None:
        text = (
            "# heading\n"
            'd.label(0x9000, "high")\n'
            'd.label(0x8000, "low")\n'
        )
        result = sort_driver_text(text)
        # The heading travels with the 0x9000 statement.
        idx_heading = result.index("# heading")
        idx_high = result.index('d.label(0x9000')
        idx_low = result.index('d.label(0x8000')
        assert idx_low < idx_heading < idx_high

    def test_blank_lines_round_trip(self) -> None:
        # Each statement carries its trailing blank with it, so a
        # one-blank-after-each-statement input round-trips: every
        # consecutive pair of statements still has whitespace
        # somewhere between them.
        text = (
            'd.label(0x9000, "high")\n'
            "\n"
            'd.label(0x8000, "low")\n'
            "\n"
        )
        result = sort_driver_text(text)
        # Both statements appear, in address order.
        parts = result.splitlines()
        non_blank = [p for p in parts if p.strip()]
        assert non_blank == [
            'd.label(0x8000, "low")',
            'd.label(0x9000, "high")',
        ]
        # The blank-line count is preserved.
        assert parts.count("") == 2

    def test_trailing_newline_round_trips(self) -> None:
        with_trailing = 'd.label(0x9000)\nd.label(0x8000)\n'
        without_trailing = 'd.label(0x9000)\nd.label(0x8000)'
        assert sort_driver_text(with_trailing).endswith("\n")
        assert not sort_driver_text(without_trailing).endswith("\n")

    def test_empty_string_round_trips(self) -> None:
        assert sort_driver_text("") == ""

    def test_already_sorted_text_passes_is_sorted(self) -> None:
        text = (
            'd.label(0x8000, "low")\n'
            'd.label(0x9000, "high")\n'
        )
        assert is_sorted(text) is True

    def test_unsorted_text_fails_is_sorted(self) -> None:
        text = (
            'd.label(0x9000, "high")\n'
            'd.label(0x8000, "low")\n'
        )
        assert is_sorted(text) is False


# --- semantic equivalence round-trip -----------------------------


class TestSemanticEquivalence:
    """Sort is a permutation of statement texts.

    For any input, the multiset of (kind, statement-text) tuples
    extracted from the units must be identical before and after
    sort. This catches drop / duplicate / mangle without needing a
    real ROM.
    """

    def _stmt_multiset(self, text: str) -> Counter[tuple[str, str]]:
        units = build_units(text)
        return Counter(
            (u.kind, "\n".join(u.statement_lines)) for u in units
        )

    def test_simple_driver_round_trip(self) -> None:
        text = (
            "import dasmos\n"
            "d = dasmos.Disassembler.create(cpu='6502')\n"
            "d.load('rom', 0x8000)\n"
            "\n"
            'd.label(0x9000, "alpha")\n'
            'd.comment(0x9000, "describes alpha")\n'
            "\n"
            'd.label(0x8000, "header")\n'
            "d.use_environment('acorn_mos')\n"
            'd.label(0xA000, "tail")\n'
            'd.subroutine(0x8500,\n'
            '    "mid",\n'
            '    description="""multi\n'
            'line""")\n'
            "ir = d.disassemble()\n"
            "output_filepath.write_text(str(ir.render('beebasm')))\n"
        )
        before = self._stmt_multiset(text)
        sorted_text = sort_driver_text(text)
        after = self._stmt_multiset(sorted_text)
        assert before == after

    def test_loop_body_round_trip(self) -> None:
        text = (
            'd.label(0x9000, "before")\n'
            "for i in range(3):\n"
            "    d.byte(0x8000 + i)\n"
            'd.label(0x8000, "after")\n'
        )
        before = self._stmt_multiset(text)
        sorted_text = sort_driver_text(text)
        after = self._stmt_multiset(sorted_text)
        assert before == after

    def test_round_trip_idempotent(self) -> None:
        # Sorting a sorted file produces the same file.
        text = (
            'd.label(0x9000, "high")\n'
            'd.label(0x8000, "low")\n'
            "d.use_environment('acorn_mos')\n"
            'd.label(0xA000, "tail")\n'
            'd.label(0xC000, "tail2")\n'
        )
        once = sort_driver_text(text)
        twice = sort_driver_text(once)
        assert once == twice
