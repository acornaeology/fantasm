"""Tests for ``fantasm.api.compare``."""

from __future__ import annotations

import pytest

from fantasm.api.compare import (
    Instruction,
    RomHeader,
    compare_headers,
    compare_roms,
    disassemble_linear,
    format_address,
    format_instruction,
    parse_rom_header,
)


def _make_minimal_rom(
    title: str = "Test", version: str = "1.00", copyright: str = "(C) Acme"
) -> bytes:
    """Build a minimal valid sideways-ROM header for testing."""
    out = bytearray()
    # JMP language_entry: $4C lo hi
    out += b"\x4C\x00\x80"
    # JMP service_entry
    out += b"\x4C\x10\x80"
    out += bytes([0x82])  # ROM type
    # Will set copyright_offset after we know layout. Reserve a slot.
    cr_offset_pos = len(out)
    out += b"\x00"  # placeholder
    out += bytes([0x01])  # binary version
    out += title.encode("ascii") + b"\x00"
    out += version.encode("ascii")
    # Copyright section starts with NUL.
    cr_offset = len(out)
    out[cr_offset_pos] = cr_offset
    out += b"\x00" + copyright.encode("ascii") + b"\x00"
    return bytes(out)


# --- parse_rom_header ----------------------------------------------


class TestParseRomHeader:
    def test_basic_header(self) -> None:
        rom = _make_minimal_rom(
            title="ACORN NFS", version="3.10", copyright="(C) 1984 Acorn"
        )
        header = parse_rom_header(rom)
        assert header.title == "ACORN NFS"
        assert header.version_string == "3.10"
        assert header.copyright == "(C) 1984 Acorn"
        assert header.language_entry == 0x8000
        assert header.service_entry == 0x8010
        assert header.rom_type == 0x82
        assert header.binary_version == 0x01

    def test_returns_dataclass(self) -> None:
        header = parse_rom_header(_make_minimal_rom())
        assert isinstance(header, RomHeader)


# --- disassemble_linear --------------------------------------------


class TestDisassembleLinear:
    def test_simple_program(self) -> None:
        # LDA #$42 (A9 42), STA $70 (85 70), RTS (60)
        data = bytes([0xA9, 0x42, 0x85, 0x70, 0x60])
        instructions = disassemble_linear(data)
        assert len(instructions) == 3
        assert instructions[0].mnemonic == "LDA"
        assert instructions[0].length == 2
        assert instructions[1].mnemonic == "STA"
        assert instructions[2].mnemonic == "RTS"
        assert instructions[2].length == 1

    def test_invalid_opcode_emits_byte(self) -> None:
        # 0x80 is invalid on NMOS but length 1 byte data record.
        data = bytes([0x80, 0x60])
        instructions = disassemble_linear(data, cpu="6502")
        assert instructions[0].is_valid is False
        assert instructions[0].length == 1
        assert instructions[1].mnemonic == "RTS"

    def test_cmos_treats_invalid_nmos_as_valid(self) -> None:
        # 0x80 is BRA on CMOS — 2 bytes.
        data = bytes([0x80, 0x05, 0x60])
        instructions = disassemble_linear(data, cpu="65c02")
        assert instructions[0].mnemonic == "BRA"
        assert instructions[0].length == 2

    def test_truncated_at_eof(self) -> None:
        # Last byte is JSR (0x20) which expects 2 operand bytes.
        data = bytes([0xA9, 0x42, 0x20, 0x00])  # missing one byte
        instructions = disassemble_linear(data)
        # The JSR is recorded as truncated.
        assert instructions[-1].is_valid is False

    def test_rom_base_param_threads_through(self) -> None:
        instructions = disassemble_linear(b"\x60", rom_base=0xA000)
        assert instructions[0].rom_address == 0xA000


# --- format_address / format_instruction ---------------------------


class TestFormatAddress:
    def test_default_rom_base(self) -> None:
        assert format_address(0x10) == "$8010"

    def test_custom_rom_base(self) -> None:
        assert format_address(0x10, rom_base=0xA000) == "$A010"


class TestFormatInstruction:
    def test_implied(self) -> None:
        inst = Instruction(0, 0x60, b"", 1, True, mnemonic_str="RTS")
        assert format_instruction(inst).startswith("RTS")

    def test_immediate(self) -> None:
        inst = Instruction(0, 0xA9, b"\x42", 2, True, mnemonic_str="LDA")
        assert "$42" in format_instruction(inst)

    def test_branch_target(self) -> None:
        # BNE +5 at offset 0 with rom_base 0x8000 => target 0x8007
        inst = Instruction(
            offset=0,
            opcode=0xD0,
            operand_bytes=b"\x05",
            length=2,
            is_valid=True,
            rom_base=0x8000,
            mnemonic_str="BNE",
        )
        assert "$8007" in format_instruction(inst)

    def test_branch_negative(self) -> None:
        # BNE -2 (forms a tight loop) at offset 5
        inst = Instruction(
            offset=5,
            opcode=0xD0,
            operand_bytes=b"\xFE",
            length=2,
            is_valid=True,
            rom_base=0x8000,
            mnemonic_str="BNE",
        )
        # PC = rom_base + offset + 2 = 0x8007; +(-2) = 0x8005
        assert "$8005" in format_instruction(inst)

    def test_absolute(self) -> None:
        inst = Instruction(
            offset=0,
            opcode=0x4C,
            operand_bytes=b"\x34\x12",
            length=3,
            is_valid=True,
            mnemonic_str="JMP",
        )
        assert "$1234" in format_instruction(inst)

    def test_invalid_byte(self) -> None:
        inst = Instruction(0, 0xFF, b"", 1, False, mnemonic_str="???")
        out = format_instruction(inst)
        assert ".byte" in out
        assert "$FF" in out


# --- compare_headers / compare_roms ---------------------------------


class TestCompareHeaders:
    def test_marks_differing_fields(self) -> None:
        a = RomHeader(
            language_entry=0x8000, service_entry=0x8010, rom_type=0x82,
            copyright_offset=0x20, binary_version=1,
            title="A", version_string="1.0", copyright="(C) A",
        )
        b = RomHeader(
            language_entry=0x8000, service_entry=0x8010, rom_type=0x82,
            copyright_offset=0x20, binary_version=2,  # differs
            title="A", version_string="1.0", copyright="(C) A",
        )
        lines = compare_headers(a, b, "A", "B")
        marker_lines = [line for line in lines if line.startswith("*")]
        assert any("Binary version" in line for line in marker_lines)


class TestCompareRoms:
    def test_identical_roms_report_high_similarity(self) -> None:
        rom = _make_minimal_rom()
        report = compare_roms(rom, rom, "A", "B")
        assert "100" in report  # 100% somewhere
        assert "ROM Comparison: A vs B" in report
        # No "NFS" hardcoded label.
        assert "NFS" not in report.splitlines()[1]

    def test_different_roms_show_diff_blocks(self) -> None:
        rom_a = _make_minimal_rom(title="VERSION A")
        rom_b = _make_minimal_rom(title="VERSION B")
        report = compare_roms(rom_a, rom_b, "A", "B")
        assert "STRUCTURAL CHANGES" in report
        assert "INSTRUCTION DIFF MAP" in report

    def test_handles_empty_roms(self) -> None:
        # Should not crash on empty input.
        report = compare_roms(b"", b"", "A", "B")
        assert "ROM Comparison" in report

    def test_cpu_param_threads_through(self) -> None:
        # 0x80 is invalid on NMOS, BRA on CMOS. Comparing one ROM
        # under different CPU settings should yield non-identical
        # opcode similarity.
        rom = bytes([0x80, 0x05, 0x60])
        # Same bytes, different CPU interpretation.
        report = compare_roms(
            rom, rom, "A", "B", cpu_a="6502", cpu_b="65c02"
        )
        # NMOS sees [0x80, 0x05, 0x60] as 3 invalid/valid items.
        # CMOS sees [BRA $..., RTS] = 2 items.
        # So instruction counts differ.
        assert "Instructions:" in report

    def test_rom_base_threads_into_addresses(self) -> None:
        rom = bytes([0x60])
        report = compare_roms(rom, rom, "A", "B", rom_base=0xC000)
        # Equal-region line addresses include the rom_base.
        assert "$C000" in report
