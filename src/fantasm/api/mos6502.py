"""MOS 6502 / WDC 65C02 instruction tables and helpers.

This module is intentionally just CPU facts — opcode lengths, mnemonics,
and a small dispatcher. Project-specific concerns like ROM base address
and bank size belong in `fantasm.toml`, not here.

Tables for both the NMOS 6502 (the ubiquitous variant) and the CMOS
65C02 / 65SC12 (used in the BBC Master 128) are exposed. Use
:func:`opcode_tables` for the common case, or read the ``OPCODE_*``
constants directly for the NMOS tables and the ``OPCODE_*_65C02``
constants for the CMOS tables.

Source for the 65C02 overrides: ``py8dis/cpu65C02.py`` in the local
fork.
"""

from __future__ import annotations


# Instruction lengths indexed by opcode byte (0-255).
# 0 = invalid/undefined, 1 = implied/accumulator,
# 2 = immediate/zp/relative, 3 = absolute.
OPCODE_LENGTHS: list[int] = [
    # $00-$0F
    1, 2, 0, 0, 0, 2, 2, 0, 1, 2, 1, 0, 0, 3, 3, 0,
    # $10-$1F
    2, 2, 0, 0, 0, 2, 2, 0, 1, 3, 0, 0, 0, 3, 3, 0,
    # $20-$2F
    3, 2, 0, 0, 2, 2, 2, 0, 1, 2, 1, 0, 3, 3, 3, 0,
    # $30-$3F
    2, 2, 0, 0, 0, 2, 2, 0, 1, 3, 0, 0, 0, 3, 3, 0,
    # $40-$4F
    1, 2, 0, 0, 0, 2, 2, 0, 1, 2, 1, 0, 3, 3, 3, 0,
    # $50-$5F
    2, 2, 0, 0, 0, 2, 2, 0, 1, 3, 0, 0, 0, 3, 3, 0,
    # $60-$6F
    1, 2, 0, 0, 0, 2, 2, 0, 1, 2, 1, 0, 3, 3, 3, 0,
    # $70-$7F
    2, 2, 0, 0, 0, 2, 2, 0, 1, 3, 0, 0, 0, 3, 3, 0,
    # $80-$8F
    0, 2, 0, 0, 2, 2, 2, 0, 1, 0, 1, 0, 3, 3, 3, 0,
    # $90-$9F
    2, 2, 0, 0, 2, 2, 2, 0, 1, 3, 1, 0, 0, 3, 0, 0,
    # $A0-$AF
    2, 2, 2, 0, 2, 2, 2, 0, 1, 2, 1, 0, 3, 3, 3, 0,
    # $B0-$BF
    2, 2, 0, 0, 2, 2, 2, 0, 1, 3, 1, 0, 3, 3, 3, 0,
    # $C0-$CF
    2, 2, 0, 0, 2, 2, 2, 0, 1, 2, 1, 0, 3, 3, 3, 0,
    # $D0-$DF
    2, 2, 0, 0, 0, 2, 2, 0, 1, 3, 0, 0, 0, 3, 3, 0,
    # $E0-$EF
    2, 2, 0, 0, 2, 2, 2, 0, 1, 2, 1, 0, 3, 3, 3, 0,
    # $F0-$FF
    2, 2, 0, 0, 0, 2, 2, 0, 1, 3, 0, 0, 0, 3, 3, 0,
]

# Mnemonics indexed by opcode byte (0-255).
# "???" for invalid/undefined opcodes on the NMOS 6502.
OPCODE_MNEMONICS: list[str] = [
    # $00-$0F
    "BRK", "ORA", "???", "???", "???", "ORA", "ASL", "???",
    "PHP", "ORA", "ASL", "???", "???", "ORA", "ASL", "???",
    # $10-$1F
    "BPL", "ORA", "???", "???", "???", "ORA", "ASL", "???",
    "CLC", "ORA", "???", "???", "???", "ORA", "ASL", "???",
    # $20-$2F
    "JSR", "AND", "???", "???", "BIT", "AND", "ROL", "???",
    "PLP", "AND", "ROL", "???", "BIT", "AND", "ROL", "???",
    # $30-$3F
    "BMI", "AND", "???", "???", "???", "AND", "ROL", "???",
    "SEC", "AND", "???", "???", "???", "AND", "ROL", "???",
    # $40-$4F
    "RTI", "EOR", "???", "???", "???", "EOR", "LSR", "???",
    "PHA", "EOR", "LSR", "???", "JMP", "EOR", "LSR", "???",
    # $50-$5F
    "BVC", "EOR", "???", "???", "???", "EOR", "LSR", "???",
    "CLI", "EOR", "???", "???", "???", "EOR", "LSR", "???",
    # $60-$6F
    "RTS", "ADC", "???", "???", "???", "ADC", "ROR", "???",
    "PLA", "ADC", "ROR", "???", "JMP", "ADC", "ROR", "???",
    # $70-$7F
    "BVS", "ADC", "???", "???", "???", "ADC", "ROR", "???",
    "SEI", "ADC", "???", "???", "???", "ADC", "ROR", "???",
    # $80-$8F
    "???", "STA", "???", "???", "STY", "STA", "STX", "???",
    "DEY", "???", "TXA", "???", "STY", "STA", "STX", "???",
    # $90-$9F
    "BCC", "STA", "???", "???", "STY", "STA", "STX", "???",
    "TYA", "STA", "TXS", "???", "???", "STA", "???", "???",
    # $A0-$AF
    "LDY", "LDA", "LDX", "???", "LDY", "LDA", "LDX", "???",
    "TAY", "LDA", "TAX", "???", "LDY", "LDA", "LDX", "???",
    # $B0-$BF
    "BCS", "LDA", "???", "???", "LDY", "LDA", "LDX", "???",
    "CLV", "LDA", "TSX", "???", "LDY", "LDA", "LDX", "???",
    # $C0-$CF
    "CPY", "CMP", "???", "???", "CPY", "CMP", "DEC", "???",
    "INY", "CMP", "DEX", "???", "CPY", "CMP", "DEC", "???",
    # $D0-$DF
    "BNE", "CMP", "???", "???", "???", "CMP", "DEC", "???",
    "CLD", "CMP", "???", "???", "???", "CMP", "DEC", "???",
    # $E0-$EF
    "CPX", "SBC", "???", "???", "CPX", "SBC", "INC", "???",
    "INX", "SBC", "NOP", "???", "CPX", "SBC", "INC", "???",
    # $F0-$FF
    "BEQ", "SBC", "???", "???", "???", "SBC", "INC", "???",
    "SED", "SBC", "???", "???", "???", "SBC", "INC", "???",
]


# 65C02 / 65SC12 (CMOS 6502, used in BBC Master 128) extends the 6502
# instruction set. Lengths and mnemonics differ from the NMOS 6502
# only at the opcodes the CMOS variant defines.
_CMOS_OVERRIDES: dict[int, tuple[int, str]] = {
    0x04: (2, "TSB"),  # TSB zp
    0x0C: (3, "TSB"),  # TSB addr
    0x12: (2, "ORA"),  # ORA (zp)
    0x14: (2, "TRB"),  # TRB zp
    0x1A: (1, "INC"),  # INC A
    0x1C: (3, "TRB"),  # TRB addr
    0x32: (2, "AND"),  # AND (zp)
    0x34: (2, "BIT"),  # BIT zp,X
    0x3A: (1, "DEC"),  # DEC A
    0x3C: (3, "BIT"),  # BIT addr,X
    0x52: (2, "EOR"),  # EOR (zp)
    0x5A: (1, "PHY"),  # PHY
    0x64: (2, "STZ"),  # STZ zp
    0x72: (2, "ADC"),  # ADC (zp)
    0x74: (2, "STZ"),  # STZ zp,X
    0x7A: (1, "PLY"),  # PLY
    0x7C: (3, "JMP"),  # JMP (addr,X)
    0x80: (2, "BRA"),  # BRA offset
    0x89: (2, "BIT"),  # BIT #imm
    0x92: (2, "STA"),  # STA (zp)
    0x9C: (3, "STZ"),  # STZ addr
    0x9E: (3, "STZ"),  # STZ addr,X
    0xB2: (2, "LDA"),  # LDA (zp)
    0xD2: (2, "CMP"),  # CMP (zp)
    0xDA: (1, "PHX"),  # PHX
    0xF2: (2, "SBC"),  # SBC (zp)
    0xFA: (1, "PLX"),  # PLX
}


def _build_cmos_tables() -> tuple[list[int], list[str]]:
    lengths = list(OPCODE_LENGTHS)
    mnemonics = list(OPCODE_MNEMONICS)
    for opcode, (length, mnemonic) in _CMOS_OVERRIDES.items():
        lengths[opcode] = length
        mnemonics[opcode] = mnemonic
    return lengths, mnemonics


OPCODE_LENGTHS_65C02, OPCODE_MNEMONICS_65C02 = _build_cmos_tables()


_CPU_ALIASES: dict[str, str] = {
    "": "6502",
    "6502": "6502",
    "nmos": "6502",
    "65c02": "65c02",
    "65sc12": "65c02",
    "65c12": "65c02",
    "cmos": "65c02",
}


def _normalise_cpu(cpu: str | None) -> str:
    key = (cpu or "6502").lower()
    if key not in _CPU_ALIASES:
        raise ValueError(f"Unknown CPU: {cpu!r}")
    return _CPU_ALIASES[key]


def opcode_tables(cpu: str | None = "6502") -> tuple[list[int], list[str]]:
    """Return ``(lengths, mnemonics)`` for the named CPU.

    Recognised values (case-insensitive): ``"6502"`` (default, NMOS),
    ``"65c02"`` (CMOS, BBC Master 128). ``"nmos"``, ``"cmos"``,
    ``"65sc12"`` and ``"65c12"`` are accepted as aliases.

    Raises ``ValueError`` for unknown CPUs.

    The returned lists are independent for each CPU family but the
    *same list objects* are returned on each call — callers must not
    mutate them.
    """
    family = _normalise_cpu(cpu)
    if family == "6502":
        return OPCODE_LENGTHS, OPCODE_MNEMONICS
    return OPCODE_LENGTHS_65C02, OPCODE_MNEMONICS_65C02


def instruction_length(opcode: int, cpu: str | None = "6502") -> int:
    """Length in bytes of the instruction starting with ``opcode``.

    Returns 0 if ``opcode`` is invalid on the named CPU.
    """
    lengths, _ = opcode_tables(cpu)
    return lengths[opcode]


def mnemonic(opcode: int, cpu: str | None = "6502") -> str:
    """Mnemonic for ``opcode`` on the named CPU.

    Returns ``"???"`` for opcodes that are invalid on the named CPU.
    """
    _, mnemonics = opcode_tables(cpu)
    return mnemonics[opcode]


# Conditional branch mnemonics — relative-addressed instructions that
# may or may not transfer control depending on the flag state.
BRANCH_MNEMONICS: frozenset[str] = frozenset(
    {"bcc", "bcs", "beq", "bne", "bmi", "bpl", "bvc", "bvs"}
)

# Mnemonics that unconditionally end a basic block / control flow.
TERMINATING_MNEMONICS: frozenset[str] = frozenset(
    {"rts", "jmp", "brk", "rti"}
)


__all__ = [
    "BRANCH_MNEMONICS",
    "OPCODE_LENGTHS",
    "OPCODE_MNEMONICS",
    "OPCODE_LENGTHS_65C02",
    "OPCODE_MNEMONICS_65C02",
    "TERMINATING_MNEMONICS",
    "opcode_tables",
    "instruction_length",
    "mnemonic",
]
