"""ROM binary comparison via ``difflib.SequenceMatcher``.

Compares two ROM images at three granularities — byte-level,
opcode-only (structural), and full instruction (opcode + operands) —
and produces a human-readable report.

Sibling ``disasm_tools.compare`` was the most diverged module
(NFS at 470 lines vs. 319 in the others). NFS is taken as the base.

Refactors relative to the sibling:

- ``ROM_BASE`` is no longer imported from ``mos6502`` — it's now a
  ``rom_base`` parameter on :func:`disassemble_linear`,
  :func:`format_address`, :func:`format_instruction`, and
  :func:`compare_roms`. The default of ``0x8000`` matches the BBC
  sideways-ROM convention.
- The hardcoded ``"NFS"`` literal in the report header is gone — the
  caller provides labels that already identify the project.
- ``Instruction`` carries ``rom_base`` so ``rom_address`` works
  without external plumbing.
- File-reading + printing wrapper deferred to ``fantasm compare``
  CLI sub-command.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from difflib import SequenceMatcher

from .mos6502 import opcode_tables


# Branch instructions use relative addressing; the operand is signed.
_BRANCH_OPCODES = frozenset(
    {0x10, 0x30, 0x50, 0x70, 0x90, 0xB0, 0xD0, 0xF0}
)


@dataclass
class Instruction:
    """One instruction from a linear sweep."""

    offset: int
    opcode: int
    operand_bytes: bytes
    length: int
    is_valid: bool
    rom_base: int = 0x8000
    mnemonic_str: str = "???"

    @property
    def rom_address(self) -> int:
        return self.rom_base + self.offset

    @property
    def all_bytes(self) -> bytes:
        return bytes([self.opcode]) + self.operand_bytes

    @property
    def mnemonic(self) -> str:
        return self.mnemonic_str


@dataclass
class RomHeader:
    """Parsed BBC Micro sideways-ROM header."""

    language_entry: int
    service_entry: int
    rom_type: int
    copyright_offset: int
    binary_version: int
    title: str
    version_string: str
    copyright: str


def parse_rom_header(data: bytes) -> RomHeader:
    """Parse the BBC Micro sideways-ROM header out of ``data``.

    Header layout (offsets from start of ROM):

    - ``+0``: ``JMP language_entry``  (3 bytes: ``$4C lo hi``)
    - ``+3``: ``JMP service_entry``   (3 bytes: ``$4C lo hi``)
    - ``+6``: ROM type byte
    - ``+7``: copyright offset (NUL preceding ``"(C)"``)
    - ``+8``: binary version
    - ``+9``: title (NUL-terminated), then version string up to the
      copyright offset, then ``"(C)..."`` NUL-terminated
    """
    language_entry = data[1] | (data[2] << 8)
    service_entry = data[4] | (data[5] << 8)
    rom_type = data[6]
    copyright_offset = data[7]
    binary_version = data[8]

    title_end = data.index(0, 9)
    title = data[9:title_end].decode("ascii", errors="replace")

    version_start = title_end + 1
    version_string = (
        data[version_start:copyright_offset]
        .rstrip(b"\x00")
        .decode("ascii", errors="replace")
    )

    copyright_start = copyright_offset + 1
    copyright_end = data.index(0, copyright_start)
    copyright = data[copyright_start:copyright_end].decode(
        "ascii", errors="replace"
    )

    return RomHeader(
        language_entry=language_entry,
        service_entry=service_entry,
        rom_type=rom_type,
        copyright_offset=copyright_offset,
        binary_version=binary_version,
        title=title,
        version_string=version_string,
        copyright=copyright,
    )


def disassemble_linear(
    data: bytes, cpu: str = "6502", rom_base: int = 0x8000
) -> list[Instruction]:
    """Decompose ``data`` into instructions via linear sweep.

    Invalid opcodes (length 0 in the table) are emitted as single
    one-byte ``???`` records. This is intentional: both ROMs in a
    comparison are swept identically, so misinterpreted data tables
    still align in the SequenceMatcher.
    """
    lengths, mnemonics = opcode_tables(cpu)
    instructions: list[Instruction] = []
    offset = 0
    while offset < len(data):
        opcode = data[offset]
        length = lengths[opcode]
        if length == 0:
            instructions.append(
                Instruction(
                    offset=offset,
                    opcode=opcode,
                    operand_bytes=b"",
                    length=1,
                    is_valid=False,
                    rom_base=rom_base,
                    mnemonic_str="???",
                )
            )
            offset += 1
        elif offset + length > len(data):
            operand = data[offset + 1:]
            instructions.append(
                Instruction(
                    offset=offset,
                    opcode=opcode,
                    operand_bytes=bytes(operand),
                    length=len(operand) + 1,
                    is_valid=False,
                    rom_base=rom_base,
                    mnemonic_str="???",
                )
            )
            break
        else:
            operand = data[offset + 1:offset + length]
            instructions.append(
                Instruction(
                    offset=offset,
                    opcode=opcode,
                    operand_bytes=bytes(operand),
                    length=length,
                    is_valid=True,
                    rom_base=rom_base,
                    mnemonic_str=mnemonics[opcode],
                )
            )
            offset += length
    return instructions


def format_address(offset: int, rom_base: int = 0x8000) -> str:
    """Format a ROM offset as ``$NNNN`` at ``rom_base + offset``."""
    return f"${rom_base + offset:04X}"


def format_instruction(inst: Instruction) -> str:
    """Format a single instruction for display.

    Examples: ``"LDA #$42 (A9 42)"``, ``".byte $FF (FF)"``.
    """
    hex_bytes = " ".join(f"{b:02X}" for b in inst.all_bytes)
    if not inst.is_valid:
        return f".byte ${inst.opcode:02X}  ({hex_bytes})"
    if inst.length == 1:
        return f"{inst.mnemonic}  ({hex_bytes})"
    if inst.length == 2:
        operand = inst.operand_bytes[0]
        if inst.opcode in _BRANCH_OPCODES:
            signed = operand if operand < 128 else operand - 256
            target = inst.rom_address + 2 + signed
            return f"{inst.mnemonic} ${target:04X}  ({hex_bytes})"
        return f"{inst.mnemonic} ${operand:02X}  ({hex_bytes})"
    addr = inst.operand_bytes[0] | (inst.operand_bytes[1] << 8)
    return f"{inst.mnemonic} ${addr:04X}  ({hex_bytes})"


def compare_headers(
    header_a: RomHeader,
    header_b: RomHeader,
    label_a: str,
    label_b: str,
) -> list[str]:
    """Return report lines comparing two ROM headers."""
    lines = []
    col_a = max(len(label_a), 14)
    col_b = max(len(label_b), 14)

    lines.append(f"  {'Field':<22s} {label_a:<{col_a}s}  {label_b:<{col_b}s}")
    lines.append(f"  {'-' * 22} {'-' * col_a}  {'-' * col_b}")

    fields = [
        ("Language entry", f"${header_a.language_entry:04X}",
         f"${header_b.language_entry:04X}"),
        ("Service entry", f"${header_a.service_entry:04X}",
         f"${header_b.service_entry:04X}"),
        ("ROM type", f"${header_a.rom_type:02X}",
         f"${header_b.rom_type:02X}"),
        ("Copyright offset", f"${header_a.copyright_offset:02X}",
         f"${header_b.copyright_offset:02X}"),
        ("Binary version", f"${header_a.binary_version:02X}",
         f"${header_b.binary_version:02X}"),
        ("Title", f'"{header_a.title}"', f'"{header_b.title}"'),
        ("Version string", f'"{header_a.version_string}"',
         f'"{header_b.version_string}"'),
        ("Copyright", f'"{header_a.copyright}"', f'"{header_b.copyright}"'),
    ]
    for name, val_a, val_b in fields:
        marker = " " if val_a == val_b else "*"
        lines.append(f"{marker} {name:<22s} {val_a:<{col_a}s}  {val_b}")

    return lines


def compare_roms(
    data_a: bytes,
    data_b: bytes,
    label_a: str,
    label_b: str,
    cpu_a: str = "6502",
    cpu_b: str = "6502",
    rom_base: int = 0x8000,
) -> str:
    """Generate the full comparison report as a single string.

    ``cpu_a`` / ``cpu_b`` select the CPU variant for each ROM (the
    two ROMs may run different CPUs, e.g. NMOS vs. CMOS). Both ROMs
    share the same ``rom_base`` for address formatting.
    """
    lines: list[str] = []

    sha256_a = hashlib.sha256(data_a).hexdigest()
    sha256_b = hashlib.sha256(data_b).hexdigest()

    byte_matcher = SequenceMatcher(None, data_a, data_b, autojunk=False)
    byte_ratio = byte_matcher.ratio()
    identical_bytes = sum(1 for a, b in zip(data_a, data_b) if a == b)

    insts_a = disassemble_linear(data_a, cpu_a, rom_base=rom_base)
    insts_b = disassemble_linear(data_b, cpu_b, rom_base=rom_base)

    opcodes_a = [inst.opcode for inst in insts_a]
    opcodes_b = [inst.opcode for inst in insts_b]
    opcode_matcher = SequenceMatcher(
        None, opcodes_a, opcodes_b, autojunk=False
    )
    opcode_ratio = opcode_matcher.ratio()

    inst_bytes_a = [inst.all_bytes for inst in insts_a]
    inst_bytes_b = [inst.all_bytes for inst in insts_b]
    inst_matcher = SequenceMatcher(
        None, inst_bytes_a, inst_bytes_b, autojunk=False
    )
    inst_ratio = inst_matcher.ratio()

    lines.append("=" * 64)
    lines.append(f"ROM Comparison: {label_a} vs {label_b}")
    lines.append("=" * 64)
    lines.append("")

    lines.append("1. SUMMARY")
    lines.append("")
    lines.append(
        f"  {label_a}: {len(data_a)} bytes  SHA-256: {sha256_a[:16]}..."
    )
    lines.append(
        f"  {label_b}: {len(data_b)} bytes  SHA-256: {sha256_b[:16]}..."
    )
    lines.append("")
    min_len = min(len(data_a), len(data_b))
    if min_len > 0:
        pct = 100 * identical_bytes / min_len
        lines.append(
            f"  Identical bytes at same offset: {identical_bytes}/{min_len} "
            f"({pct:.1f}%)"
        )
    lines.append(f"  Byte-level similarity:         {byte_ratio:.1%} (SequenceMatcher)")
    lines.append(f"  Opcode-level similarity:       {opcode_ratio:.1%} (structure only)")
    lines.append(
        f"  Full instruction similarity:   {inst_ratio:.1%} (opcode + operands)"
    )
    lines.append(
        f"  Instructions: {len(insts_a)} ({label_a}) / {len(insts_b)} ({label_b})"
    )
    lines.append("")

    lines.append("2. ROM HEADER")
    lines.append("")
    try:
        header_a = parse_rom_header(data_a)
        header_b = parse_rom_header(data_b)
        lines.extend(compare_headers(header_a, header_b, label_a, label_b))
    except (ValueError, IndexError) as exc:
        lines.append(f"  Error parsing headers: {exc}")
    lines.append("")

    lines.append("3. STRUCTURAL CHANGES (opcode-level)")
    lines.append("")
    opcode_ops = opcode_matcher.get_opcodes()
    n_equal = sum(1 for tag, *_ in opcode_ops if tag == "equal")
    n_replace = sum(1 for tag, *_ in opcode_ops if tag == "replace")
    n_delete = sum(1 for tag, *_ in opcode_ops if tag == "delete")
    n_insert = sum(1 for tag, *_ in opcode_ops if tag == "insert")
    n_changes = n_replace + n_delete + n_insert

    lines.append(
        f"  {n_changes} change blocks "
        f"({n_replace} replaced, {n_delete} deleted, {n_insert} inserted), "
        f"{n_equal} equal regions"
    )
    lines.append("")

    _emit_diff_block(
        lines, opcode_ops, insts_a, insts_b, label_a, label_b, rom_base
    )
    lines.append("")

    lines.append("4. INSTRUCTION DIFF MAP (opcode + operands)")
    lines.append("")
    inst_ops = inst_matcher.get_opcodes()
    _emit_diff_block(
        lines, inst_ops, insts_a, insts_b, label_a, label_b, rom_base
    )

    return "\n".join(lines)


def _emit_diff_block(
    lines: list[str],
    ops: list[tuple],
    insts_a: list[Instruction],
    insts_b: list[Instruction],
    label_a: str,
    label_b: str,
    rom_base: int,
) -> None:
    """Append diff lines for one set of SequenceMatcher opcodes."""
    for tag, i1, i2, j1, j2 in ops:
        if tag == "equal":
            a_start = format_address(insts_a[i1].offset, rom_base)
            a_end = format_address(insts_a[i2 - 1].offset, rom_base)
            b_start = format_address(insts_b[j1].offset, rom_base)
            b_end = format_address(insts_b[j2 - 1].offset, rom_base)
            lines.append(
                f"  == {a_start}-{a_end} / {b_start}-{b_end}: "
                f"{i2 - i1} instructions"
            )
        elif tag == "replace":
            lines.append(f"  ~~ REPLACE {i2 - i1} -> {j2 - j1} instructions:")
            for k in range(i1, i2):
                inst = insts_a[k]
                lines.append(
                    f"     {label_a} {format_address(inst.offset, rom_base)}: "
                    f"{format_instruction(inst)}"
                )
            for k in range(j1, j2):
                inst = insts_b[k]
                lines.append(
                    f"     {label_b} {format_address(inst.offset, rom_base)}: "
                    f"{format_instruction(inst)}"
                )
        elif tag == "delete":
            lines.append(f"  -- DELETE {i2 - i1} instructions from {label_a}:")
            for k in range(i1, i2):
                inst = insts_a[k]
                lines.append(
                    f"     {label_a} {format_address(inst.offset, rom_base)}: "
                    f"{format_instruction(inst)}"
                )
        elif tag == "insert":
            lines.append(f"  ++ INSERT {j2 - j1} instructions in {label_b}:")
            for k in range(j1, j2):
                inst = insts_b[k]
                lines.append(
                    f"     {label_b} {format_address(inst.offset, rom_base)}: "
                    f"{format_instruction(inst)}"
                )


__all__ = [
    "Instruction",
    "RomHeader",
    "compare_headers",
    "compare_roms",
    "disassemble_linear",
    "format_address",
    "format_instruction",
    "parse_rom_header",
]
