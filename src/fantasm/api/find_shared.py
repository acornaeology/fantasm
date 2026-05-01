"""Find shared 6502 code fragments between ROM binaries.

Compares opcode sequences between a "primary" ROM and one or more
"reference" ROMs via ``difflib.SequenceMatcher``. Operand bytes are
ignored, so instructions with different operands but the same opcode
(e.g. ``LDA &1234`` vs. ``LDA &5678``) still register as
structurally identical.

Originally an EBR-only sibling module. The fantasm port keeps the
pure-logic surface (sweep, span finding, byte counting, spec
parsing) and defers the print-and-argparse top-level entry to CLI
integration.
"""

from __future__ import annotations

import difflib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from .mos6502 import OPCODE_LENGTHS


@dataclass(frozen=True)
class Instruction:
    offset: int
    opcode: int
    length: int


@dataclass
class RomData:
    """An opcode sweep of a ROM, paired with a load address."""

    label: str
    load_addr: int
    data: bytes
    instructions: list[Instruction]
    opcodes: list[int]

    def runtime_addr(self, instruction_index: int) -> int:
        return self.load_addr + self.instructions[instruction_index].offset


def sweep_opcodes(data: bytes) -> tuple[list[Instruction], list[int]]:
    """Naive linear sweep: every byte is treated as an instruction start.

    Robust across dispatch tables and relocated blocks. Matching spans
    in the output are suggestive, not authoritative.
    """
    instructions: list[Instruction] = []
    offset = 0
    while offset < len(data):
        opcode = data[offset]
        length = OPCODE_LENGTHS[opcode]
        if length == 0 or offset + length > len(data):
            length = 1
        instructions.append(Instruction(offset, opcode, length))
        offset += length
    opcodes = [i.opcode for i in instructions]
    return instructions, opcodes


def load_rom(label: str, filepath: str | Path, load_addr: int) -> RomData:
    """Load a ROM and prepare it for comparison."""
    data = Path(filepath).read_bytes()
    instructions, opcodes = sweep_opcodes(data)
    return RomData(label, load_addr, data, instructions, opcodes)


def is_trivial_span(
    opcodes: Sequence[int], start: int, length: int, min_distinct: int = 3
) -> bool:
    """Span is trivial if it has fewer than ``min_distinct`` distinct opcodes.

    Filters out spurious matches in ROM padding (runs of ``&FF`` or
    ``&00``) and degenerate patterns like a single RTS surrounded by
    padding.
    """
    window = opcodes[start:start + length]
    return len(set(window)) < min_distinct


def find_matching_spans(
    primary: RomData,
    reference: RomData,
    min_len: int,
    *,
    reject_trivial: bool = True,
) -> list[tuple[int, int, int]]:
    """Return ``(primary_idx, reference_idx, length)`` for every matching block.

    Only blocks of at least ``min_len`` instructions are returned.
    Trivial spans (per :func:`is_trivial_span`) are rejected unless
    ``reject_trivial=False``.
    """
    matcher = difflib.SequenceMatcher(
        a=primary.opcodes, b=reference.opcodes, autojunk=False
    )
    matches: list[tuple[int, int, int]] = []
    for block in matcher.get_matching_blocks():
        if block.size < min_len:
            continue
        if reject_trivial and is_trivial_span(
            primary.opcodes, block.a, block.size
        ):
            continue
        matches.append((block.a, block.b, block.size))
    return matches


def matching_byte_count(
    primary: RomData,
    matches: Iterable[tuple[int, int, int]],
) -> int:
    """Sum of instruction byte-lengths across matching spans in ``primary``."""
    total = 0
    for a_idx, _, size in matches:
        for i in range(a_idx, a_idx + size):
            total += primary.instructions[i].length
    return total


def parse_rom_spec(spec: str) -> tuple[str, Path, int]:
    """Parse a ROM spec ``[label=]path@load-addr`` into ``(label, path, addr)``.

    Address accepts hex (``&E000``, ``0xE000``, ``$E000``) or
    decimal. If ``label=`` is omitted, the file stem is used. Raises
    ``ValueError`` for malformed specs and ``FileNotFoundError`` when
    the path doesn't exist.
    """
    if "=" in spec:
        label, rest = spec.split("=", 1)
    else:
        label, rest = None, spec
    if "@" not in rest:
        raise ValueError(f"ROM spec must include @<load-addr>: {spec!r}")
    path_str, addr_str = rest.rsplit("@", 1)
    cleaned = addr_str.strip().lstrip("$&").removeprefix("0x")
    try:
        load_addr = int(cleaned, 16)
    except ValueError as exc:
        raise ValueError(
            f"invalid load address in {spec!r}: {addr_str!r}"
        ) from exc
    filepath = Path(path_str).expanduser()
    if not filepath.exists():
        raise FileNotFoundError(f"ROM file not found: {filepath}")
    if label is None:
        label = filepath.stem
    return label, filepath, load_addr


__all__ = [
    "Instruction",
    "RomData",
    "find_matching_spans",
    "is_trivial_span",
    "load_rom",
    "matching_byte_count",
    "parse_rom_spec",
    "sweep_opcodes",
]
