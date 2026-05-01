"""Characterisation tests for ``fantasm.api.mos6502``.

Pin down well-known opcode encodings (LDA, JMP, RTS, NOP, JSR, ...) and
the CMOS overrides (BRA, PHX, INC A, ...). The opcode tables are
foundational; if they break, almost everything downstream miscompiles.
"""

from __future__ import annotations

import pytest

from fantasm.api import mos6502


class TestNmosTables:
    def test_lengths_is_256_entries(self) -> None:
        assert len(mos6502.OPCODE_LENGTHS) == 256

    def test_mnemonics_is_256_entries(self) -> None:
        assert len(mos6502.OPCODE_MNEMONICS) == 256

    @pytest.mark.parametrize(
        "opcode, expected_length, expected_mnemonic",
        [
            (0x00, 1, "BRK"),
            (0x20, 3, "JSR"),  # JSR abs
            (0x4C, 3, "JMP"),  # JMP abs
            (0x60, 1, "RTS"),
            (0x40, 1, "RTI"),
            (0xA9, 2, "LDA"),  # LDA #imm
            (0xAD, 3, "LDA"),  # LDA abs
            (0xA5, 2, "LDA"),  # LDA zp
            (0x8D, 3, "STA"),  # STA abs
            (0xEA, 1, "NOP"),
            (0x18, 1, "CLC"),
            (0x38, 1, "SEC"),
            (0xD0, 2, "BNE"),  # branches are 2 bytes (rel)
            (0xF0, 2, "BEQ"),
            (0x10, 2, "BPL"),
            (0x30, 2, "BMI"),
            (0x50, 2, "BVC"),
            (0x70, 2, "BVS"),
            (0x90, 2, "BCC"),
            (0xB0, 2, "BCS"),
        ],
    )
    def test_well_known_opcodes(
        self, opcode: int, expected_length: int, expected_mnemonic: str
    ) -> None:
        assert mos6502.OPCODE_LENGTHS[opcode] == expected_length
        assert mos6502.OPCODE_MNEMONICS[opcode] == expected_mnemonic

    @pytest.mark.parametrize(
        "opcode",
        [
            # Opcodes that are invalid on NMOS but defined on CMOS.
            0x1A,  # INC A on CMOS
            0x3A,  # DEC A on CMOS
            0x5A,  # PHY on CMOS
            0x7A,  # PLY on CMOS
            0x80,  # BRA on CMOS
            0xDA,  # PHX on CMOS
            0xFA,  # PLX on CMOS
        ],
    )
    def test_cmos_only_opcodes_are_invalid_on_nmos(self, opcode: int) -> None:
        # NMOS treats these as undefined: length 0, mnemonic "???".
        assert mos6502.OPCODE_LENGTHS[opcode] == 0
        assert mos6502.OPCODE_MNEMONICS[opcode] == "???"


class TestCmosTables:
    def test_lengths_is_256_entries(self) -> None:
        assert len(mos6502.OPCODE_LENGTHS_65C02) == 256

    def test_mnemonics_is_256_entries(self) -> None:
        assert len(mos6502.OPCODE_MNEMONICS_65C02) == 256

    @pytest.mark.parametrize(
        "opcode, expected_length, expected_mnemonic",
        [
            # CMOS-only instructions.
            (0x1A, 1, "INC"),  # INC A
            (0x3A, 1, "DEC"),  # DEC A
            (0x5A, 1, "PHY"),
            (0x7A, 1, "PLY"),
            (0x80, 2, "BRA"),
            (0xDA, 1, "PHX"),
            (0xFA, 1, "PLX"),
            (0x12, 2, "ORA"),  # ORA (zp)
            (0x32, 2, "AND"),  # AND (zp)
            (0x52, 2, "EOR"),  # EOR (zp)
            (0x72, 2, "ADC"),  # ADC (zp)
            (0x92, 2, "STA"),  # STA (zp)
            (0xB2, 2, "LDA"),  # LDA (zp)
            (0xD2, 2, "CMP"),  # CMP (zp)
            (0xF2, 2, "SBC"),  # SBC (zp)
            (0x89, 2, "BIT"),  # BIT #imm
            (0x9C, 3, "STZ"),  # STZ abs
            (0x7C, 3, "JMP"),  # JMP (abs,X)
            # Instructions that are unchanged from NMOS — sanity check.
            (0x00, 1, "BRK"),
            (0x20, 3, "JSR"),
            (0x60, 1, "RTS"),
            (0xA9, 2, "LDA"),
        ],
    )
    def test_cmos_overrides(
        self, opcode: int, expected_length: int, expected_mnemonic: str
    ) -> None:
        assert mos6502.OPCODE_LENGTHS_65C02[opcode] == expected_length
        assert mos6502.OPCODE_MNEMONICS_65C02[opcode] == expected_mnemonic

    def test_cmos_does_not_mutate_nmos_tables(self) -> None:
        # The CMOS tables are independent copies — mutating one must
        # not affect the other.
        assert mos6502.OPCODE_LENGTHS is not mos6502.OPCODE_LENGTHS_65C02
        assert mos6502.OPCODE_MNEMONICS is not mos6502.OPCODE_MNEMONICS_65C02


class TestOpcodeTables:
    def test_default_returns_nmos(self) -> None:
        lengths, mnemonics = mos6502.opcode_tables()
        assert lengths is mos6502.OPCODE_LENGTHS
        assert mnemonics is mos6502.OPCODE_MNEMONICS

    @pytest.mark.parametrize("alias", ["6502", "NMOS", "nmos", "", None])
    def test_nmos_aliases(self, alias: str | None) -> None:
        lengths, mnemonics = mos6502.opcode_tables(alias)
        assert lengths is mos6502.OPCODE_LENGTHS
        assert mnemonics is mos6502.OPCODE_MNEMONICS

    @pytest.mark.parametrize("alias", ["65c02", "65C02", "65sc12", "65c12", "cmos", "CMOS"])
    def test_cmos_aliases(self, alias: str) -> None:
        lengths, mnemonics = mos6502.opcode_tables(alias)
        assert lengths is mos6502.OPCODE_LENGTHS_65C02
        assert mnemonics is mos6502.OPCODE_MNEMONICS_65C02

    def test_unknown_cpu_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown CPU"):
            mos6502.opcode_tables("z80")


class TestHelpers:
    def test_instruction_length_nmos(self) -> None:
        assert mos6502.instruction_length(0xA9) == 2
        assert mos6502.instruction_length(0x4C) == 3
        assert mos6502.instruction_length(0x60) == 1
        # Invalid on NMOS.
        assert mos6502.instruction_length(0x80) == 0

    def test_instruction_length_cmos(self) -> None:
        # 0x80 is BRA on CMOS — 2 bytes.
        assert mos6502.instruction_length(0x80, "65c02") == 2
        # 0x1A is INC A on CMOS — 1 byte.
        assert mos6502.instruction_length(0x1A, "cmos") == 1

    def test_mnemonic_nmos(self) -> None:
        assert mos6502.mnemonic(0xA9) == "LDA"
        assert mos6502.mnemonic(0x4C) == "JMP"
        assert mos6502.mnemonic(0x80) == "???"

    def test_mnemonic_cmos(self) -> None:
        assert mos6502.mnemonic(0x80, "65c02") == "BRA"
        assert mos6502.mnemonic(0xDA, "cmos") == "PHX"
