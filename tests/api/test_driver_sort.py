"""Tests for ``fantasm.api.driver_sort``.

Three layers:

1. **Classifier unit tests** — small hand-written snippets that pin
   one decision each (each kind is recognised; literals are
   extracted; non-literal first args become soft anchors; etc.).

2. **Canonical-ordering tests** — the new topo-sort produces a
   single canonical order. Each test asserts a specific output
   order rather than "in-run is non-decreasing".

3. **Semantic equivalence round-trip** — the multiset of
   statement texts is preserved across sort.

The synthetic-ROM byte-identity oracle lives in a separate test
module so it can be skipped cleanly when dasmos isn't importable.
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


def _kinds(text: str) -> list[str]:
    return [u.kind for u in build_units(text)]


def _addresses(text: str) -> list[int | None]:
    return [u.address for u in build_units(text)]


# --- classifier ----------------------------------------------------


class TestClassifier:
    def test_label_call_with_hex_addr_is_annotation(self) -> None:
        text = 'd.label(0x9000, "foo")\n'
        assert _kinds(text) == ["annotation"]
        assert _addresses(text) == [0x9000]

    def test_bare_label_call_also_annotation(self) -> None:
        # py8dis-style import-* drivers omit the ``d.`` receiver.
        text = 'label(0x9000, "foo")\n'
        assert _kinds(text) == ["annotation"]

    def test_decimal_addr_is_accepted(self) -> None:
        text = 'd.label(36864, "foo")\n'  # 0x9000
        assert _kinds(text) == ["annotation"]
        assert _addresses(text) == [36864]

    def test_non_literal_first_arg_is_soft_anchor(self) -> None:
        # ``0x9286 + i`` doesn't reduce to a literal at top level —
        # but it would inside a for-loop body. At top level: soft anchor.
        text = "d.byte(some_var)\n"
        assert _kinds(text) == ["soft_anchor"]

    def test_each_sortable_kind_recognised(self) -> None:
        kinds = [
            "label", "comment", "subroutine", "banner", "entry",
            "byte", "word", "string", "expr", "expr_label",
            "rts_code_ptr", "hook_subroutine", "format_hint",
        ]
        for kind in kinds:
            text = f"d.{kind}(0x9000)\n"
            assert _kinds(text) == ["annotation"], kind

    def test_use_environment_classified(self) -> None:
        text = "d.use_environment('acorn_mos')\n"
        assert _kinds(text) == ["use_environment"]

    def test_add_move_with_three_literals_classified(self) -> None:
        text = "d.add_move(0x0500, 0x9465, 0x100)\n"
        units = build_units(text)
        assert units[0].kind == "add_move"
        assert units[0].address == 0x0500  # min(dest, src)

    def test_add_move_with_non_literal_is_soft_anchor(self) -> None:
        text = "d.add_move(dest, src, length)\n"
        assert _kinds(text) == ["soft_anchor"]

    def test_constant_with_literal_value_classified(self) -> None:
        text = "d.constant(0xFEA0, 'adlc_cr1')\n"
        units = build_units(text)
        assert units[0].kind == "constant"
        assert units[0].address == 0xFEA0

    def test_render_start_classified(self) -> None:
        text = "ir = d.disassemble()\n"
        assert _kinds(text) == ["render_start"]

    def test_imports_assigns_create_load_are_setup(self) -> None:
        text = (
            "import dasmos\n"
            "from pathlib import Path\n"
            "_dirpath = Path('.')\n"
            "d = dasmos.Disassembler.create(cpu='6502')\n"
            "d.load('rom', 0x8000)\n"
        )
        assert _kinds(text) == [
            "setup_import", "setup_import",
            "setup_assign", "setup_assign", "setup_load",
        ]


# --- multi-line statements ----------------------------------------


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
        assert [u.kind for u in units] == ["annotation", "annotation"]
        # Subroutine block keeps its 4 lines together.
        assert len(units[0].statement_lines) == 4
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
        assert units[0].kind == "annotation"
        assert units[0].address == 0xABCD


# --- canonical ordering -------------------------------------------


class TestCanonicalOrdering:
    def test_two_annotations_get_reordered(self) -> None:
        text = (
            'd.label(0x9000, "high")\n'
            'd.label(0x8000, "low")\n'
        )
        result = sort_driver_text(text)
        first = result.index('d.label(0x8000')
        second = result.index('d.label(0x9000')
        assert first < second

    def test_already_sorted_is_unchanged(self) -> None:
        text = (
            'd.label(0x8000, "low")\n'
            'd.label(0x9000, "high")\n'
        )
        assert sort_driver_text(text) == text

    def test_use_environment_clusters_ahead_of_addressed_run(self) -> None:
        # A label originally before use_environment must NOT be
        # stranded — it sorts into the address run with everything
        # else, and the env cluster lands between setup and the
        # address run.
        text = (
            'import dasmos\n'
            "d = dasmos.Disassembler.create(cpu='6502')\n"
            "d.load('rom', 0x8000)\n"
            'd.label(0xBFC5, "stranded_in_0_12")\n'
            "d.use_environment('acorn_mos')\n"
            "d.use_environment('acorn_master')\n"
            'd.label(0x0050, "low_addr")\n'
            'd.label(0xA000, "mid_addr")\n'
        )
        result = sort_driver_text(text)
        lines = [ln for ln in result.splitlines() if ln.strip()]
        # Setup at top.
        assert lines[0] == "import dasmos"
        assert lines[1] == "d = dasmos.Disassembler.create(cpu='6502')"
        assert lines[2] == "d.load('rom', 0x8000)"
        # Env cluster next, in source order.
        assert lines[3] == "d.use_environment('acorn_mos')"
        assert lines[4] == "d.use_environment('acorn_master')"
        # Then the address run, in address order.
        assert lines[5] == 'd.label(0x0050, "low_addr")'
        assert lines[6] == 'd.label(0xA000, "mid_addr")'
        assert lines[7] == 'd.label(0xBFC5, "stranded_in_0_12")'

    def test_render_coda_stays_at_bottom(self) -> None:
        text = (
            'd.label(0x9000, "high")\n'
            'd.label(0x8000, "low")\n'
            "ir = d.disassemble()\n"
            "output_filepath.write_text(str(ir.render('beebasm')))\n"
        )
        result = sort_driver_text(text)
        lines = [ln for ln in result.splitlines() if ln.strip()]
        assert lines[0] == 'd.label(0x8000, "low")'
        assert lines[1] == 'd.label(0x9000, "high")'
        assert lines[2] == "ir = d.disassemble()"
        assert lines[3] == "output_filepath.write_text(str(ir.render('beebasm')))"

    def test_late_import_in_render_coda_stays_in_coda(self) -> None:
        # An ``import sys`` placed just before the render block in
        # source must NOT be pulled to the top with the other
        # imports — it's part of the render-coda region.
        text = (
            "import dasmos\n"
            'd.label(0x9000, "x")\n'
            "import sys\n"
            "ir = d.disassemble()\n"
            "print('done', file=sys.stderr)\n"
        )
        result = sort_driver_text(text)
        lines = [ln for ln in result.splitlines() if ln.strip()]
        # First import at top; second `import sys` sits with render.
        assert lines[0] == "import dasmos"
        assert lines[1] == 'd.label(0x9000, "x")'
        assert lines[2] == "import sys"
        assert lines[3] == "ir = d.disassemble()"
        assert lines[4] == "print('done', file=sys.stderr)"

    def test_hook_subroutine_sorts_by_address(self) -> None:
        text = (
            'd.label(0xA000, "anchor_a000")\n'
            "d.hook_subroutine(0x9000, 'inline', stringhi_hook)\n"
            'd.label(0xB000, "anchor_b000")\n'
        )
        result = sort_driver_text(text)
        lines = [ln for ln in result.splitlines() if ln.strip()]
        # The hook sorts to its address position (0x9000) — it does
        # NOT cluster as "setup" any more.
        assert lines[0] == "d.hook_subroutine(0x9000, 'inline', stringhi_hook)"
        assert lines[1] == 'd.label(0xA000, "anchor_a000")'
        assert lines[2] == 'd.label(0xB000, "anchor_b000")'

    def test_constant_sorts_by_value(self) -> None:
        text = (
            'd.label(0x8000, "low")\n'
            "d.constant(0xFEA0, 'adlc_cr1')\n"
            'd.label(0x9000, "mid")\n'
        )
        result = sort_driver_text(text)
        lines = [ln for ln in result.splitlines() if ln.strip()]
        assert lines[0] == 'd.label(0x8000, "low")'
        assert lines[1] == 'd.label(0x9000, "mid")'
        assert lines[2] == "d.constant(0xFEA0, 'adlc_cr1')"

    def test_add_move_floats_to_dest_position(self) -> None:
        text = (
            'd.label(0xA000, "anchor_high")\n'
            "d.add_move(0x0500, 0x9465, 0x100)\n"
            'd.label(0x0500, "moved_label")\n'
            'd.label(0x0050, "low_workspace")\n'
        )
        result = sort_driver_text(text)
        lines = [ln for ln in result.splitlines() if ln.strip()]
        # add_move sits next to its dest range — and the moved_label
        # at 0x0500 stays adjacent because of the topology edge.
        assert lines[0] == 'd.label(0x0050, "low_workspace")'
        assert lines[1] == "d.add_move(0x0500, 0x9465, 0x100)"
        assert lines[2] == 'd.label(0x0500, "moved_label")'
        assert lines[3] == 'd.label(0xA000, "anchor_high")'

    def test_loop_anchored_at_iterable_first_literal(self) -> None:
        text = (
            'd.label(0x8000, "before")\n'
            "for addr in range(0x9000, 0x9010):\n"
            "    d.byte(addr)\n"
            'd.label(0x7000, "below")\n'
        )
        result = sort_driver_text(text)
        lines = [ln for ln in result.splitlines() if ln.strip()]
        # 0x7000 first, then 0x8000, then the loop (anchored at 0x9000).
        assert lines[0] == 'd.label(0x7000, "below")'
        assert lines[1] == 'd.label(0x8000, "before")'
        assert lines[2] == "for addr in range(0x9000, 0x9010):"
        assert lines[3] == "    d.byte(addr)"

    def test_loop_anchored_at_body_first_literal(self) -> None:
        # Header has no literal; body's d.byte(0x9286 + i) recovers 0x9286.
        text = (
            'd.label(0xA000, "after")\n'
            "for i in range(11):\n"
            "    d.byte(0x9286 + i)\n"
            'd.label(0x8000, "before")\n'
        )
        result = sort_driver_text(text)
        lines = [ln for ln in result.splitlines() if ln.strip()]
        assert lines[0] == 'd.label(0x8000, "before")'
        assert lines[1] == "for i in range(11):"
        assert lines[2] == "    d.byte(0x9286 + i)"
        assert lines[3] == 'd.label(0xA000, "after")'

    def test_loop_over_module_level_table_of_tuples_anchors_at_first_addr(
        self,
    ) -> None:
        # Issue #14 reproducer pattern: a for-loop iterates over a
        # module-level list of (addr, label, desc) tuples, with the
        # body emitting d.word(addr) on the iter var. Sort must
        # follow the Name back to the literal list and recover the
        # covered addresses (0x0500, 0x0502, …, 0x0516 here).
        text = (
            "_table = [(0x0500, 'x'), (0x0510, 'y')]\n"
            'd.label(0x9000, "after_table_run")\n'
            "for addr, label in _table:\n"
            "    d.word(addr)\n"
            'd.label(0x0400, "before_table_run")\n'
        )
        result = sort_driver_text(text)
        lines = [ln for ln in result.splitlines() if ln.strip()]
        # 0x0400 before, then the loop (covers 0x0500..0x0510),
        # then 0x9000.
        assert lines[0] == "_table = [(0x0500, 'x'), (0x0510, 'y')]"
        assert lines[1] == 'd.label(0x0400, "before_table_run")'
        assert lines[2] == "for addr, label in _table:"
        assert lines[3] == "    d.word(addr)"
        assert lines[4] == 'd.label(0x9000, "after_table_run")'

    def test_loop_must_follow_add_move_covering_loop_addresses(self) -> None:
        # Direct issue #14 case: ``add_move`` mapping bytes into
        # 0x0500-0x0600, and a for-loop emitting d.word at literal
        # 0x0500-0x0510. The loop MUST sort after the move, so the
        # move's translation table is registered before the
        # annotations attach.
        text = (
            "_table = [(0x0500, 'x'), (0x0510, 'y')]\n"
            "for addr, label in _table:\n"
            "    d.word(addr)\n"
            "d.add_move(0x0500, 0xBC90, 0x100)\n"
        )
        result = sort_driver_text(text)
        lines = [ln for ln in result.splitlines() if ln.strip()]
        # add_move first, then the loop, with the table at the top.
        idx_table = result.index("_table = ")
        idx_move = result.index("d.add_move(")
        idx_for = result.index("for addr, label")
        assert idx_table < idx_move < idx_for

    def test_loop_with_unknown_coverage_pinned_after_every_add_move(
        self,
    ) -> None:
        # Conservative over-constrain rule: if we can't fully
        # determine the loop's covered addresses, every add_move
        # must precede it. Here the iterable is a function call we
        # don't recognise, so coverage is unknown.
        text = (
            "d.add_move(0x0500, 0xBC90, 0x100)\n"
            "d.add_move(0x0600, 0xBD90, 0x100)\n"
            "for x in load_table():\n"
            "    d.byte(x)\n"
        )
        result = sort_driver_text(text)
        idx_move_1 = result.index("d.add_move(0x0500")
        idx_move_2 = result.index("d.add_move(0x0600")
        idx_for = result.index("for x in load_table")
        assert idx_move_1 < idx_for
        assert idx_move_2 < idx_for

    def test_loop_with_no_recoverable_address_inherits_from_predecessor(
        self,
    ) -> None:
        # Loop iterating over a Name with body using a Name first arg
        # — no derivable literal anywhere. Falls back to soft anchor,
        # which inherits the sort key of the nearest preceding
        # addressable statement.
        text = (
            'd.label(0x9000, "predecessor")\n'
            "for x in some_iterable:\n"
            "    d.byte(x)\n"
            'd.label(0x9001, "after_loop")\n'
        )
        result = sort_driver_text(text)
        lines = [ln for ln in result.splitlines() if ln.strip()]
        # Loop inherits 0x9000's key, tiebreaks by source position
        # (after the 0x9000 label, before the 0x9001 label).
        assert lines[0] == 'd.label(0x9000, "predecessor")'
        assert lines[1] == "for x in some_iterable:"
        assert lines[2] == "    d.byte(x)"
        assert lines[3] == 'd.label(0x9001, "after_loop")'

    def test_hex_literals_preserved_verbatim(self) -> None:
        # Mix of upper and lower hex digits — must NOT be normalised.
        text = (
            'd.label(0xfeA0, "weird-case")\n'
            'd.label(0xBfC7, "another")\n'
        )
        result = sort_driver_text(text)
        assert "0xfeA0" in result
        assert "0xBfC7" in result
        # No decimal conversion either.
        assert "65184" not in result
        assert "49095" not in result

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

    def test_idempotent(self) -> None:
        text = (
            'import dasmos\n'
            "d = dasmos.Disassembler.create(cpu='6502')\n"
            "d.load('rom', 0x8000)\n"
            'd.label(0x9000, "alpha")\n'
            "d.use_environment('acorn_mos')\n"
            'd.label(0x8000, "header")\n'
            "ir = d.disassemble()\n"
            "output_filepath.write_text(str(ir.render('beebasm')))\n"
        )
        once = sort_driver_text(text)
        twice = sort_driver_text(once)
        assert once == twice


# --- module-level name / data dependencies (issue #15) ------------


class TestNameDependencies:
    """The sort must not break intra-module name / data flow.

    A statement that writes a module-level name must precede later
    statements that read or reassign it; read-only relationships (the
    ``d`` receiver) stay free. See issue #15.
    """

    def _order(self, text: str) -> list[str]:
        return [ln for ln in sort_driver_text(text).splitlines() if ln.strip()]

    def test_accumulator_setup_precedes_its_consumer_loop(self) -> None:
        # Case A: ``addr = 0x8579`` initialises a free variable that the
        # loop reads and reassigns. The assignment must stay ahead of
        # the loop even though intervening annotations sort between them.
        text = (
            "d.label(0x8000, 'header')\n"
            "addr = 0x8579\n"
            "for _ in range(7):\n"
            "    d.byte(addr, 1)\n"
            "    addr = d.stringz(addr + 1)\n"
            "d.label(0x8100, 'mid')\n"
        )
        order = self._order(text)
        i_setup = order.index("addr = 0x8579")
        i_loop = order.index("for _ in range(7):")
        assert i_setup < i_loop

    def test_no_other_writer_falls_between_setup_and_consumer(self) -> None:
        # The consumer loop is anchored high (body literal 0x9000); a
        # competing ``addr`` writer is anchored low (0x8000). Only the
        # name edge stops the low writer sorting between the setup and
        # the consumer — which is exactly the #15 corruption.
        text = (
            "addr = 0x8579\n"
            "for _ in range(7):\n"
            "    d.byte(0x9000)\n"
            "    d.byte(addr, 1)\n"
            "    addr = d.stringz(addr + 1)\n"
            "for addr in range(0x8000, 0x8002):\n"
            "    d.byte(addr)\n"
        )
        order = self._order(text)
        i_setup = order.index("addr = 0x8579")
        i_consumer = order.index("for _ in range(7):")
        i_other = order.index("for addr in range(0x8000, 0x8002):")
        assert i_setup < i_consumer < i_other

    def test_while_accumulator_setup_precedes_loop(self) -> None:
        # Case B(a): the ``while`` variant of the free-variable loop.
        text = (
            "d.label(0x8000, 'header')\n"
            "_kw = 0x8071\n"
            "while _kw < 0x8100:\n"
            "    _kw = d.string(_kw)\n"
            "d.label(0x8200, 'tail')\n"
        )
        order = self._order(text)
        assert order.index("_kw = 0x8071") < order.index("while _kw < 0x8100:")

    def test_def_precedes_its_module_level_caller(self) -> None:
        # Case B(b): a module-level ``def`` used by an assignment must
        # not sort after the call site (would be a NameError). The file
        # must still sort — not fall back to a no-op.
        text = (
            "d.label(0x9000, 'tail')\n"
            "def _parse(rom, start, end):\n"
            "    return []\n"
            "ENTRIES = _parse(_rom, 0x8071, 0x8100)\n"
            "d.label(0x8000, 'header')\n"
        )
        order = self._order(text)
        i_def = order.index("def _parse(rom, start, end):")
        i_call = order.index("ENTRIES = _parse(_rom, 0x8071, 0x8100)")
        assert i_def < i_call
        # And the annotations still sorted by address around them.
        assert order.index("d.label(0x8000, 'header')") < order.index(
            "d.label(0x9000, 'tail')"
        )

    def test_shared_receiver_reads_do_not_freeze_the_sort(self) -> None:
        # Every ``d.X(…)`` reads ``d``, but read-after-read is not a
        # dependency — the annotations must still reorder by address.
        text = (
            "d = dasmos.Disassembler.create(cpu='6502')\n"
            "d.label(0x9000, 'high')\n"
            "d.label(0x8000, 'low')\n"
        )
        order = self._order(text)
        assert order.index("d.label(0x8000, 'low')") < order.index(
            "d.label(0x9000, 'high')"
        )

    def test_cyclic_dependencies_leave_file_unchanged(self) -> None:
        # A non-setup loop writes ``rom_path``, which the setup
        # ``d.load(…)`` reads — this closes a cycle with the
        # setup→non-setup edge. No valid canonical order exists, so the
        # sort is a no-op and ``is_sorted`` reports True.
        text = (
            "d = dasmos.Disassembler.create(cpu='6502')\n"
            "for _ in range(1):\n"
            "    rom_path = 'rom.bin'\n"
            "d.load(rom_path, 0x8000)\n"
            "d.label(0x9000, 'x')\n"
            "d.label(0x8000, 'y')\n"
        )
        assert sort_driver_text(text) == text
        assert is_sorted(text) is True


# --- semantic equivalence round-trip ------------------------------


class TestSemanticEquivalence:
    """Sort is a permutation of statement texts.

    The multiset of (kind, statement-text) tuples extracted from
    the units must be identical before and after sort. This catches
    drop / duplicate / mangle without needing a real ROM.
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

    def test_accumulator_loop_round_trip(self) -> None:
        # The free-variable accumulator pattern (issue #15) is a
        # permutation like any other — no statement dropped or mangled.
        text = (
            "addr = 0x8579\n"
            "for _ in range(7):\n"
            "    d.byte(addr, 1)\n"
            "    addr = d.stringz(addr + 1)\n"
            'd.label(0x8000, "header")\n'
        )
        before = self._stmt_multiset(text)
        sorted_text = sort_driver_text(text)
        after = self._stmt_multiset(sorted_text)
        assert before == after
