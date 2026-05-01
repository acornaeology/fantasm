"""Opcode-level address mapping between two ROM versions.

Provides a primary LCS-based mapping (``difflib.SequenceMatcher`` on
opcode sequences — order-preserving, so it cannot follow code that
has been reordered or relocated between versions) and a supplementary
seed-and-extend pass (k-gram seeds + alignment, borrowed from
bioinformatics) that catches moved blocks.

Sibling ``disasm_tools.blockmatch`` was NFS-only (the cross-version
NFS work needed it). The fantasm port is essentially verbatim except
that ``ROM_BASE`` was lifted out of ``mos6502`` — the helpers now
take ``rom_base`` as a parameter (default ``0x8000``).

Returns address mappings as ``dict[int, int]`` keyed by ROM address
(e.g. ``0xA000 -> 0xA1B4``).
"""

from __future__ import annotations

import difflib
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from .mos6502 import opcode_tables


def disassemble_to_opcodes(
    data: bytes, cpu: str = "6502"
) -> list[tuple[int, int, int]]:
    """Linear sweep returning ``(offset, opcode, length)`` tuples.

    Invalid opcodes (length 0 in the table) advance one byte. ``cpu``
    selects between ``"6502"`` and ``"65c02"``.
    """
    lengths, _ = opcode_tables(cpu)
    instructions: list[tuple[int, int, int]] = []
    offset = 0
    while offset < len(data):
        opcode = data[offset]
        length = lengths[opcode] or 1
        instructions.append((offset, opcode, length))
        offset += length
    return instructions


def build_primary_map(
    insts_a: Sequence[tuple[int, int, int]],
    insts_b: Sequence[tuple[int, int, int]],
    rom_base: int = 0x8000,
) -> dict[int, int]:
    """LCS-based opcode mapping. Order-preserving; misses reorders."""
    opcodes_a = [op for _, op, _ in insts_a]
    opcodes_b = [op for _, op, _ in insts_b]
    matcher = difflib.SequenceMatcher(
        None, opcodes_a, opcodes_b, autojunk=False
    )
    addr_map: dict[int, int] = {}
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for d in range(i2 - i1):
                addr_map[rom_base + insts_a[i1 + d][0]] = (
                    rom_base + insts_b[j1 + d][0]
                )
    return addr_map


@dataclass(frozen=True)
class RelocatedBlock:
    """A region of ROM A matched to a moved region in ROM B."""

    a_start_addr: int  # inclusive
    a_end_addr: int  # exclusive
    b_start_addr: int
    b_end_addr: int
    ratio: float  # opcode-level similarity in [0.0, 1.0]
    matched_pairs: int  # address mappings produced from this block
    a_opcodes: int  # opcodes in the A window
    b_opcodes: int  # opcodes in the B window


def find_relocated_blocks(
    insts_a: Sequence[tuple[int, int, int]],
    insts_b: Sequence[tuple[int, int, int]],
    primary_addr_map: dict[int, int],
    *,
    rom_base: int = 0x8000,
    k: int = 6,
    min_seeds: int = 2,
    max_seed_gap: int = 8,
    min_block_opcodes: int = 8,
    min_ratio: float = 0.85,
) -> tuple[dict[int, int], list[RelocatedBlock]]:
    """Find supplementary opcode-level mappings via k-mer seed-and-extend.

    Conflicts inside the supplementary pass (one A or B instruction
    claimed by two clusters) are resolved greedily by ratio.
    Conflicts with the primary map are not allowed: the primary map
    is authoritative.

    Returns ``(supplementary_map, blocks)``. ``supplementary_map`` has
    no overlap with ``primary_addr_map``.
    """
    if len(insts_a) < k or len(insts_b) < k:
        return {}, []

    primary_b_addrs = set(primary_addr_map.values())
    a_pinned = [
        (rom_base + off) in primary_addr_map for off, _, _ in insts_a
    ]
    b_pinned = [
        (rom_base + off) in primary_b_addrs for off, _, _ in insts_b
    ]

    opcodes_a = bytes(op for _, op, _ in insts_a)
    opcodes_b = bytes(op for _, op, _ in insts_b)

    # Index k-mers over unmatched B.
    b_index: dict[bytes, list[int]] = defaultdict(list)
    for j in range(len(opcodes_b) - k + 1):
        if any(b_pinned[j + d] for d in range(k)):
            continue
        b_index[opcodes_b[j:j + k]].append(j)

    # Collect seeds, bucket by alignment delta.
    seeds_by_delta: dict[int, list[tuple[int, int]]] = defaultdict(list)
    for i in range(len(opcodes_a) - k + 1):
        if any(a_pinned[i + d] for d in range(k)):
            continue
        kmer = opcodes_a[i:i + k]
        if kmer in b_index:
            for j in b_index[kmer]:
                seeds_by_delta[j - i].append((i, j))

    # Chain seeds with bounded gaps within each delta bucket.
    candidates: list[tuple[int, int, int, int]] = []
    for delta, seeds in seeds_by_delta.items():
        if len(seeds) < min_seeds:
            continue
        seeds.sort()
        chain = [seeds[0]]
        for s in seeds[1:]:
            if s[0] - chain[-1][0] <= max_seed_gap:
                chain.append(s)
            else:
                if len(chain) >= min_seeds:
                    i_lo = chain[0][0]
                    i_hi = chain[-1][0] + k
                    j_lo = chain[0][1]
                    j_hi = chain[-1][1] + k
                    candidates.append((i_lo, i_hi, j_lo, j_hi))
                chain = [s]
        if len(chain) >= min_seeds:
            i_lo = chain[0][0]
            i_hi = chain[-1][0] + k
            j_lo = chain[0][1]
            j_hi = chain[-1][1] + k
            candidates.append((i_lo, i_hi, j_lo, j_hi))

    # Score each candidate via SequenceMatcher on the window.
    aligned: list[tuple[float, int, int, list, int, int]] = []
    for i_lo, i_hi, j_lo, j_hi in candidates:
        a_len = i_hi - i_lo
        b_len = j_hi - j_lo
        if a_len < min_block_opcodes or b_len < min_block_opcodes:
            continue
        a_win = opcodes_a[i_lo:i_hi]
        b_win = opcodes_b[j_lo:j_hi]
        sm = difflib.SequenceMatcher(None, a_win, b_win, autojunk=False)
        ratio = sm.ratio()
        if ratio < min_ratio:
            continue
        aligned.append(
            (ratio, i_lo, j_lo, sm.get_matching_blocks(), a_len, b_len)
        )

    # Greedy assignment by descending ratio.
    aligned.sort(key=lambda t: -t[0])
    used_a: set[int] = set()
    used_b: set[int] = set()
    supplementary: dict[int, int] = {}
    blocks: list[RelocatedBlock] = []

    for ratio, i_lo, j_lo, mblocks, a_len, b_len in aligned:
        added_pairs = 0
        first_a = first_b = None
        last_a_end = last_b_end = None
        for mb in mblocks:
            for d in range(mb.size):
                a_idx = i_lo + mb.a + d
                b_idx = j_lo + mb.b + d
                if a_idx in used_a or b_idx in used_b:
                    continue
                if a_pinned[a_idx] or b_pinned[b_idx]:
                    continue
                addr_a = rom_base + insts_a[a_idx][0]
                addr_b = rom_base + insts_b[b_idx][0]
                if addr_a in primary_addr_map:
                    continue
                if addr_a in supplementary:
                    continue
                supplementary[addr_a] = addr_b
                used_a.add(a_idx)
                used_b.add(b_idx)
                added_pairs += 1
                if first_a is None:
                    first_a = addr_a
                    first_b = addr_b
                last_a_end = addr_a + insts_a[a_idx][2]
                last_b_end = addr_b + insts_b[b_idx][2]
        if added_pairs > 0 and first_a is not None:
            blocks.append(
                RelocatedBlock(
                    a_start_addr=first_a,
                    a_end_addr=last_a_end,
                    b_start_addr=first_b,
                    b_end_addr=last_b_end,
                    ratio=ratio,
                    matched_pairs=added_pairs,
                    a_opcodes=a_len,
                    b_opcodes=b_len,
                )
            )

    return supplementary, blocks


def build_full_address_map(
    data_a: bytes,
    data_b: bytes,
    cpu_a: str = "6502",
    cpu_b: str = "6502",
    *,
    rom_base: int = 0x8000,
    **kwargs,
) -> tuple[dict[int, int], dict[int, int], dict[int, int], list[RelocatedBlock]]:
    """Primary + supplementary opcode-level address map in one call.

    Returns ``(full_map, primary_map, supplementary_map, blocks)``.
    Primary mappings take precedence on conflict.
    """
    insts_a = disassemble_to_opcodes(data_a, cpu_a)
    insts_b = disassemble_to_opcodes(data_b, cpu_b)
    primary = build_primary_map(insts_a, insts_b, rom_base=rom_base)
    supplementary, blocks = find_relocated_blocks(
        insts_a, insts_b, primary, rom_base=rom_base, **kwargs
    )
    full = dict(primary)
    full.update(supplementary)
    return full, primary, supplementary, blocks


__all__ = [
    "RelocatedBlock",
    "build_full_address_map",
    "build_primary_map",
    "disassemble_to_opcodes",
    "find_relocated_blocks",
]
