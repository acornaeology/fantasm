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


# Three-byte fixture: LDA #$42 ; RTS at base 0x8000.
SYNTHETIC_ROM_BYTES = bytes([0xA9, 0x42, 0x60])
SYNTHETIC_ROM_BASE = 0x8000


def _make_driver_text(rom_filepath: Path) -> str:
    """Driver text that intentionally declares annotations out of order.

    The header banner at &8000 appears LAST, the RTS comment in the
    middle, and an &8001 comment first — so a working sort produces
    a strict 8000 → 8001 → 8002 order by addresses, ascending.
    """
    return (
        "import dasmos\n"
        "d = dasmos.Disassembler.create(cpu='6502')\n"
        f"d.load({str(rom_filepath)!r}, 0x{SYNTHETIC_ROM_BASE:04X})\n"
        "\n"
        "d.comment(0x8001, 'immediate value: 0x42')\n"
        "d.comment(0x8002, 'return from synthetic stub')\n"
        "d.label(0x8000, 'synthetic_entry')\n"
        "d.banner(0x8000, title='Synthetic 3-byte fixture')\n"
        "d.entry(0x8000)\n"
        "d.comment(0x8000, 'load A with 0x42')\n"
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

    def test_addresses_are_in_order_after_sort(self, tmp_path: Path) -> None:
        # Independent check that the sort actually reorders: the
        # 0x8000 banner/label/entry/comment cluster appears before
        # the 0x8001 and 0x8002 comments in the sorted output.
        rom_filepath = tmp_path / "synthetic.rom"
        rom_filepath.write_bytes(SYNTHETIC_ROM_BYTES)

        sorted_driver_text = sort_driver_text(_make_driver_text(rom_filepath))
        idx_8000 = sorted_driver_text.index("d.label(0x8000")
        idx_8001 = sorted_driver_text.index("d.comment(0x8001")
        idx_8002 = sorted_driver_text.index("d.comment(0x8002")
        assert idx_8000 < idx_8001 < idx_8002
