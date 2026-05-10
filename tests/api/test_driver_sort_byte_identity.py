"""Byte-identity round-trip test for ``fantasm.api.driver_sort``.

The promise of ``sort_driver_text`` is that it permutes whole
statement texts without changing semantics — re-running the driver
before and after sort must produce byte-identical disassembler
output (the same contract ``fantasm verify`` enforces against real
ROMs).

This test exercises that promise on a tiny synthetic fixture: a
3-byte ROM (``LDA #$42`` ``RTS``) and a driver that intentionally
declares its annotations out of address order so the sort has work
to do. We then ``exec`` the driver in-process (before and after
sort) and compare ``ir.render('beebasm')`` and ``ir.render('json')``.

Skipped when ``dasmos`` isn't importable in the test environment —
fantasm itself doesn't depend on it (the disassembler is a
workflow tool, not a runtime dep), so CI without dasmos installed
will skip cleanly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

dasmos = pytest.importorskip("dasmos")


from fantasm.api.driver_sort import sort_driver_text


# 16-byte fixture: a couple of LDA/STA/RTS sequences plus four
# bytes of trailing data. Enough surface to land annotations in
# every kind we care about (label, comment, banner, entry, byte,
# constant) and exercise a for-loop emitting per-byte annotations.
SYNTHETIC_ROM_BYTES = bytes([
    0xA9, 0x42,       # &8000  LDA #&42
    0x85, 0x70,       # &8002  STA &70
    0xA9, 0x00,       # &8004  LDA #&00
    0x85, 0x71,       # &8006  STA &71
    0x60,             # &8008  RTS
    0x00, 0x01, 0x02, 0x03,  # &8009..&800C  data run
    0xFF, 0xFF, 0xFF,        # &800D..&800F  padding
])
SYNTHETIC_ROM_BASE = 0x8000


def _make_driver_text(rom_filepath: Path) -> str:
    """Driver text that exercises the new sort path's constructs.

    Annotations are declared deliberately out of address order, with
    a hex constant near the top, an entry / banner pair after some
    middle-address comments, a for-loop emitting bytes for the data
    run, and a high-address banner before a low-address label. A
    correct topological sort lands every annotation at its primary
    address, with the for-loop anchored at the first iteration's
    literal.
    """
    return (
        "import dasmos\n"
        "d = dasmos.Disassembler.create(cpu='6502')\n"
        f"d.load({str(rom_filepath)!r}, 0x{SYNTHETIC_ROM_BASE:04X})\n"
        "\n"
        "d.comment(0x8002, 'store low byte of 0x42 into &70')\n"
        "d.comment(0x8006, 'store low byte of 0x00 into &71')\n"
        "d.label(0x8004, 'reset_high')\n"
        "d.constant(0x70, 'wksp_lo')\n"
        "d.banner(0x800D, title='Trailing FF padding')\n"
        "d.label(0x8000, 'synthetic_entry')\n"
        "d.banner(0x8000, title='Synthetic 16-byte fixture')\n"
        "d.entry(0x8000)\n"
        "d.comment(0x8000, 'load A with 0x42')\n"
        "d.constant(0x71, 'wksp_hi')\n"
        "for addr in range(0x8009, 0x800D):\n"
        "    d.byte(addr)\n"
        "d.comment(0x8008, 'return from synthetic stub')\n"
    )


def _run_driver(driver_text: str) -> tuple[str, str]:
    """Execute ``driver_text`` and return ``(beebasm_output, json_output)``."""
    namespace: dict[str, object] = {}
    exec(compile(driver_text, "<driver>", "exec"), namespace)  # noqa: S102
    d = namespace["d"]
    ir = d.disassemble()  # type: ignore[attr-defined]
    return str(ir.render("beebasm")), str(ir.render("json"))


class TestSortPreservesDasmosOutput:
    def test_byte_identical_render(self, tmp_path: Path) -> None:
        rom_filepath = tmp_path / "synthetic.rom"
        rom_filepath.write_bytes(SYNTHETIC_ROM_BYTES)

        driver_text = _make_driver_text(rom_filepath)
        sorted_driver_text = sort_driver_text(driver_text)
        assert sorted_driver_text != driver_text, (
            "fixture should not already be sorted — otherwise this "
            "test isn't exercising the sort path"
        )

        beebasm_before, json_before = _run_driver(driver_text)
        beebasm_after, json_after = _run_driver(sorted_driver_text)

        assert beebasm_before == beebasm_after
        assert json_before == json_after

    def test_loop_emitting_on_moved_range_keeps_classifications(
        self, tmp_path: Path
    ) -> None:
        """Issue #14 regression test.

        A ``for``-loop that iterates over a module-level table of
        ``(addr, label, …)`` tuples and emits ``d.word(addr) ;
        d.expr(addr, label)`` on the iter var must sort AFTER the
        ``d.add_move(dest, src, length)`` whose dest range covers
        those addresses. If it sorts before, the annotations attach
        to runtime addresses with no binary↔runtime mapping yet
        registered and dasmos silently drops the ``equw`` /
        ``equb`` classifications, the symbolic expressions, and
        the per-entry comments.

        The byte-identity test from ``test_byte_identical_render``
        doesn't catch this — the underlying bytes assemble
        identically — so this case lives in its own test asserting
        on the rendered text.
        """
        # 16-byte ROM. Bytes 4..7 are a 2-entry word table whose
        # values are pointers into the same ROM (sym_a at &8000,
        # sym_b at &8002). At runtime these 4 bytes live at &0100.
        rom_bytes = bytes([
            0xA9, 0x00,         # &8000  sym_a: LDA #&00
            0x60, 0x60,         # &8002  sym_b: RTS ; padding
            0x00, 0x80,         # &8004  word &8000 (= sym_a) - moved to &0100
            0x02, 0x80,         # &8006  word &8002 (= sym_b) - moved to &0102
            0xFF, 0xFF, 0xFF, 0xFF,  # &8008..&800B  padding
            0xFF, 0xFF, 0xFF, 0xFF,  # &800C..&800F  padding
        ])
        rom_filepath = tmp_path / "issue_14.rom"
        rom_filepath.write_bytes(rom_bytes)

        # Driver text: well-formed, with the move ahead of the
        # loop in source order. A correct sort must keep the
        # loop after the move; without the issue #14 fix it
        # would shuffle the loop ahead of the move and the
        # rendered output would differ.
        driver_text = (
            "import dasmos\n"
            "from dasmos import Align\n"
            "d = dasmos.Disassembler.create(cpu='6502')\n"
            f"d.load({str(rom_filepath)!r}, 0x8000)\n"
            "\n"
            "d.add_move(0x0100, 0x8004, 0x4)\n"
            "d.label(0x8000, 'sym_a')\n"
            "d.label(0x8002, 'sym_b')\n"
            "d.entry(0x8000)\n"
            "_dispatch = [(0x0100, 'sym_a', 'first'), "
            "(0x0102, 'sym_b', 'second')]\n"
            "for addr, target, desc in _dispatch:\n"
            "    d.word(addr)\n"
            "    d.expr(addr, target)\n"
            "    d.comment(addr, desc, align=Align.INLINE)\n"
        )

        sorted_driver_text = sort_driver_text(driver_text)
        beebasm_before, json_before = _run_driver(driver_text)
        beebasm_after, json_after = _run_driver(sorted_driver_text)

        assert beebasm_before == beebasm_after
        assert json_before == json_after
        # The rendered .asm should carry symbolic ``equw sym_a``
        # for the dispatch table — proof that classifications
        # attached with the move's mapping in place.
        assert "equw sym_a" in beebasm_after
        assert "equw sym_b" in beebasm_after

    def test_addresses_are_in_order_after_sort(self, tmp_path: Path) -> None:
        # Independent check that the sort actually reorders: the
        # 0x8000 cluster precedes 0x8002, 0x8004, 0x8006, 0x8008 and
        # the 0x800D banner. The for-loop's iteration starts at
        # 0x8009 so it sorts between 0x8008 and 0x800D.
        rom_filepath = tmp_path / "synthetic.rom"
        rom_filepath.write_bytes(SYNTHETIC_ROM_BYTES)

        sorted_text = sort_driver_text(_make_driver_text(rom_filepath))
        idx_8000_label = sorted_text.index("d.label(0x8000")
        idx_8002 = sorted_text.index("d.comment(0x8002")
        idx_8004 = sorted_text.index("d.label(0x8004")
        idx_8008 = sorted_text.index("d.comment(0x8008")
        idx_loop = sorted_text.index("for addr in range(0x8009")
        idx_800d_banner = sorted_text.index("d.banner(0x800D")
        assert (
            idx_8000_label
            < idx_8002
            < idx_8004
            < idx_8008
            < idx_loop
            < idx_800d_banner
        )
