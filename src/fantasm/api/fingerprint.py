"""Build short structural "fingerprints" of ROM regions.

Used to spot near-duplicate code blocks across ROM versions, often
as a cross-check for the :mod:`fantasm.api.blockmatch` results.

NFS-only sibling module. Ported with the same ``ROM_BASE`` lift-out
as the rest of the suite (``rom_base`` is now a parameter; default
``0x8000``).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from .blockmatch import disassemble_to_opcodes


def opcode_fingerprint(opcodes: bytes) -> str:
    """Stable short hash of a sequence of opcodes."""
    return hashlib.sha1(opcodes, usedforsecurity=False).hexdigest()[:16]


def fingerprint_window(
    data: bytes,
    offset: int,
    length: int,
    cpu: str = "6502",
) -> str:
    """Fingerprint the opcodes covering ``data[offset:offset+length]``.

    The window is sliced at the byte level; instructions whose first
    byte is outside the window are ignored.
    """
    insts = disassemble_to_opcodes(data, cpu)
    op_bytes = bytes(
        op for off, op, _ in insts if offset <= off < offset + length
    )
    return opcode_fingerprint(op_bytes)


def fingerprint_blocks(
    data: bytes,
    block_size: int = 64,
    cpu: str = "6502",
    rom_base: int = 0x8000,
) -> dict[int, str]:
    """Fingerprint each ``block_size``-byte block of ``data``.

    Returns ``{rom_address -> fingerprint}`` keyed by the block's
    starting ROM address.
    """
    out: dict[int, str] = {}
    for offset in range(0, len(data), block_size):
        out[rom_base + offset] = fingerprint_window(
            data, offset, block_size, cpu
        )
    return out


def find_duplicate_blocks(
    fingerprints: dict[int, str]
) -> dict[str, list[int]]:
    """Group addresses by fingerprint; keep groups with 2+ addresses."""
    by_fingerprint: dict[str, list[int]] = {}
    for addr, fp in fingerprints.items():
        by_fingerprint.setdefault(fp, []).append(addr)
    return {fp: addrs for fp, addrs in by_fingerprint.items() if len(addrs) >= 2}


def fingerprint_rom_file(
    rom_filepath: str | Path,
    block_size: int = 64,
    cpu: str = "6502",
    rom_base: int = 0x8000,
) -> dict[int, str]:
    """Convenience: load a ROM and fingerprint its blocks."""
    return fingerprint_blocks(
        Path(rom_filepath).read_bytes(),
        block_size=block_size,
        cpu=cpu,
        rom_base=rom_base,
    )


__all__ = [
    "find_duplicate_blocks",
    "fingerprint_blocks",
    "fingerprint_rom_file",
    "fingerprint_window",
    "opcode_fingerprint",
]
