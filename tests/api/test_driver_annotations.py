"""Tests for ``fantasm.api.driver_annotations``."""

from __future__ import annotations

import pytest

from fantasm.api.driver_annotations import (
    DriverParseError,
    parse_driver_annotations,
)


PY8DIS_DRIVER = '''\
import py8dis

comment(0x8005, "first instruction", inline=True)
comment(0x8006, "block comment")
subroutine(0x8000, "init", hook=None)
subroutine(0x8050,
    "load_data",
    hook=None,
    is_entry_point=False)
label(0x8100, "data_table")
label(0x8200)
'''


DASMOS_DRIVER = '''\
import dasmos
from dasmos import Align

d = dasmos.Disassembler.create(cpu="6502")
d.load("rom.bin", 0x8000)

d.label(0x0010, "zp_temp", length=1, group="zero_page")
d.comment(0x8430, "Transfer to X", align=Align.INLINE)
d.comment(0x8431, "Above the line")
d.subroutine(
    0x8430,
    "transfer",
    title="Transfer (with a paren)",
    description="""Multi-line description with (parens)
and 0x8430 inside it.""",
)
d.comment(0x8000 + 3, "Offset literal", align=Align.INLINE)

for idx in range(4):
    d.comment(0x9000 + idx, "entry %d" % idx, align=Align.INLINE)

ir = d.disassemble()
'''


class TestPy8disDialect:
    def test_kinds_in_source_order(self) -> None:
        anns = parse_driver_annotations(PY8DIS_DRIVER)
        assert [a.kind for a in anns] == [
            "comment", "comment", "subroutine", "subroutine", "label", "label",
        ]

    def test_inline_flag(self) -> None:
        anns = parse_driver_annotations(PY8DIS_DRIVER)
        assert [a.inline for a in anns if a.kind == "comment"] == [True, False]

    def test_names_and_entry_points(self) -> None:
        subs = [
            a for a in parse_driver_annotations(PY8DIS_DRIVER)
            if a.kind == "subroutine"
        ]
        assert [(s.name, s.is_entry_point) for s in subs] == [
            ("init", True), ("load_data", False),
        ]

    def test_label_without_name(self) -> None:
        labels = [
            a for a in parse_driver_annotations(PY8DIS_DRIVER)
            if a.kind == "label"
        ]
        assert [(a.address, a.name) for a in labels] == [
            (0x8100, "data_table"), (0x8200, None),
        ]


class TestDasmosDialect:
    def test_receiver_method_calls_are_found(self) -> None:
        anns = parse_driver_annotations(DASMOS_DRIVER)
        assert [(a.kind, a.address) for a in anns] == [
            ("label", 0x0010),
            ("comment", 0x8430),
            ("comment", 0x8431),
            ("subroutine", 0x8430),
            ("comment", 0x8003),
        ]

    def test_align_inline(self) -> None:
        comments = {
            a.address: a for a in parse_driver_annotations(DASMOS_DRIVER)
            if a.kind == "comment"
        }
        assert comments[0x8430].inline
        assert comments[0x8430].text == "Transfer to X"
        assert not comments[0x8431].inline

    def test_subroutine_with_address_on_next_line(self) -> None:
        (sub,) = [
            a for a in parse_driver_annotations(DASMOS_DRIVER)
            if a.kind == "subroutine"
        ]
        assert sub.name == "transfer"
        assert sub.line_number == 10
        assert sub.end_line_number == 16
        assert sub.source.startswith("d.subroutine(\n    0x8430,")
        assert sub.source.endswith(")")

    def test_computed_addresses_are_skipped(self) -> None:
        addresses = {a.address for a in parse_driver_annotations(DASMOS_DRIVER)}
        assert not any(0x9000 <= addr < 0x9004 for addr in addresses)

    def test_constant_offset_address_is_folded(self) -> None:
        addresses = {a.address for a in parse_driver_annotations(DASMOS_DRIVER)}
        assert 0x8003 in addresses


def test_unrelated_calls_are_ignored() -> None:
    text = 'x.comment("not an address")\nlabel(some_variable, "n")\n'
    assert parse_driver_annotations(text) == []


def test_syntax_error_raises_driver_parse_error() -> None:
    with pytest.raises(DriverParseError, match="line 1"):
        parse_driver_annotations("d.comment(0x8000,\n")
