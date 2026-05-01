"""Back-propagate annotations between ROM versions.

Builds an opcode-level confidence map between two ROM images and
parses py8dis driver scripts to extract their annotations
(``comment``/``label``/``subroutine`` calls). Together these let
annotations from a richly-annotated version flow back to less
annotated ones via the high-confidence portion of the address map.

Sibling ``disasm_tools.backfill`` (621 lines, byte-identical across
forks) carried two heavy NFS-specific pieces:

- ``VERSION_CHAIN`` — adjacent-version pairs and their relocation
  blocks, hardcoded for NFS.
- ``build_chained_map`` and the top-level ``backfill()`` — file-IO,
  printing, and version-chain walking that depends on the above.

The fantasm port lifts the **pure helpers** out:
:func:`build_confidence_map`, :func:`build_confidence_map_for_block`,
:func:`group_logical_statements`, :func:`parse_annotations`,
:func:`translate_address_in_text`, :func:`translate_subroutine`.

Project-specific concerns are parameters now: ``rom_base`` (was a
module-level constant) and ``workspace_ranges`` (was hardcoded as
``range(0x0000, 0x0100)`` plus NFS's ``range(0x0D00, 0x1000)``).
A future fantasm.toml schema will let projects declare their own
version chains; ``build_chained_map`` will land then alongside the
``fantasm backfill`` Click sub-command.
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Iterable, Sequence
from pathlib import Path

from .blockmatch import disassemble_to_opcodes


# Default workspace ranges: zero page only. NFS extended this with
# 0x0D00-0x0FFF; pass workspace_ranges=[(0, 0x100), (0xD00, 0x1000)]
# (or whatever a project's `[audit] memory_regions` defines) to match.
_DEFAULT_WORKSPACE_RANGES: tuple[tuple[int, int], ...] = (
    (0x0000, 0x0100),
)


def build_confidence_map_for_block(
    insts_a: Sequence[tuple[int, int, int]],
    insts_b: Sequence[tuple[int, int, int]],
    base_a: int,
    base_b: int,
) -> dict[int, tuple[int, int]]:
    """Build ``{addr_a: (addr_b, block_length)}`` from two instruction lists.

    ``base_a``/``base_b`` are added to raw offsets to produce final
    addresses. ``block_length`` is the number of consecutive matching
    opcodes in the enclosing equal block — the confidence signal.
    """
    opcodes_a = [op for _, op, _ in insts_a]
    opcodes_b = [op for _, op, _ in insts_b]

    matcher = difflib.SequenceMatcher(
        None, opcodes_a, opcodes_b, autojunk=False
    )

    conf_map: dict[int, tuple[int, int]] = {}
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            block_length = i2 - i1
            for k in range(block_length):
                addr_a = base_a + insts_a[i1 + k][0]
                addr_b = base_b + insts_b[j1 + k][0]
                conf_map[addr_a] = (addr_b, block_length)
    return conf_map


def build_confidence_map(
    data_a: bytes,
    data_b: bytes,
    reloc_blocks: Iterable[tuple[int, int, int, int]] = (),
    *,
    rom_base: int = 0x8000,
    workspace_ranges: Iterable[tuple[int, int]] = _DEFAULT_WORKSPACE_RANGES,
    high_confidence: int = 1000,
    cpu: str = "6502",
) -> dict[int, tuple[int, int]]:
    """Full confidence map between two ROM versions.

    ``reloc_blocks`` is an iterable of
    ``(src_a, src_b, runtime_dest, length)`` tuples describing
    relocated code — each block is matched separately at its runtime
    destination and merged in. ``workspace_ranges`` get identity
    mappings at ``high_confidence`` so labels for workspace variables
    propagate even when no opcodes anchor them.

    Returns ``{addr_a: (addr_b, block_length)}``.
    """
    insts_a = disassemble_to_opcodes(data_a, cpu)
    insts_b = disassemble_to_opcodes(data_b, cpu)

    conf_map = build_confidence_map_for_block(
        insts_a, insts_b, rom_base, rom_base
    )

    reloc_destination_addrs: set[int] = set()
    for src_a, src_b, dest, length in reloc_blocks:
        block_a = data_a[src_a - rom_base:src_a - rom_base + length]
        block_b = data_b[src_b - rom_base:src_b - rom_base + length]
        reloc_insts_a = disassemble_to_opcodes(block_a, cpu)
        reloc_insts_b = disassemble_to_opcodes(block_b, cpu)
        conf_map.update(
            build_confidence_map_for_block(
                reloc_insts_a, reloc_insts_b, dest, dest
            )
        )
        for a in range(dest, dest + length):
            reloc_destination_addrs.add(a)

    # Identity mappings for workspace addresses (excluding any address
    # already occupied by a relocated block — those addresses are code
    # at runtime, not workspace).
    for start, end in workspace_ranges:
        for addr in range(start, end):
            if addr in conf_map:
                continue
            if addr in reloc_destination_addrs:
                continue
            conf_map[addr] = (addr, high_confidence)

    return conf_map


# --- Annotation parsing -------------------------------------------


# Regex for inline comments: comment(0xADDR, "text", inline=True)
RE_INLINE_COMMENT = re.compile(
    r'^comment\(0x([0-9A-Fa-f]+),\s*"((?:[^"\\]|\\.)*)"\s*,\s*inline\s*=\s*True\)',
    re.MULTILINE,
)
RE_LABEL = re.compile(
    r'^label\(0x([0-9A-Fa-f]+),\s*"([^"]+)"',
    re.MULTILINE,
)
RE_SUBROUTINE = re.compile(
    r'^subroutine\(0x([0-9A-Fa-f]+)',
    re.MULTILINE,
)


def group_logical_statements(
    lines: Sequence[str],
) -> list[tuple[int, int, list[str]]]:
    """Group lines into balanced-paren statements.

    Returns ``(start_line_idx, end_line_idx_exclusive, lines_list)``
    tuples. Quoted strings and ``#`` comments are skipped when
    counting parens.
    """
    groups: list[tuple[int, int, list[str]]] = []
    current_start = 0
    current_lines: list[str] = []
    paren_depth = 0
    in_string: str | None = None
    escaped = False

    for i, line in enumerate(lines):
        current_lines.append(line)

        for j, ch in enumerate(line):
            if in_string is None:
                if ch == "#":
                    break
                if ch in ('"', "'"):
                    triple = line[j:j + 3]
                    if triple in ('"""', "'''"):
                        in_string = triple
                    else:
                        in_string = ch
                elif ch == "(":
                    paren_depth += 1
                elif ch == ")":
                    paren_depth -= 1
            else:
                if escaped:
                    escaped = False
                    continue
                if len(in_string) == 3 and line[j:j + 3] == in_string:
                    in_string = None
                elif len(in_string) == 1 and ch == in_string:
                    in_string = None
                elif ch == "\\":
                    escaped = True

        if paren_depth <= 0:
            paren_depth = 0
            groups.append((current_start, i + 1, current_lines))
            current_start = i + 1
            current_lines = []

    if current_lines:
        groups.append(
            (current_start, current_start + len(current_lines), current_lines)
        )

    return groups


def parse_annotations(
    script_text: str,
) -> tuple[
    dict[int, list[tuple[str, str]]],
    dict[int, tuple[str, str]],
    set[str],
    dict[int, str],
]:
    """Parse driver-script text and return its annotations.

    Returns ``(inline_comments, labels, label_names, subroutines)``:

    - ``inline_comments``: ``{addr -> [(text, full_line), ...]}``
    - ``labels``: ``{addr -> (name, full_line)}`` — last label wins
    - ``label_names``: set of every label name encountered
    - ``subroutines``: ``{addr -> full_statement_text}`` (may be
      multi-line)
    """
    lines = script_text.split("\n")
    groups = group_logical_statements(lines)

    inline_comments: dict[int, list[tuple[str, str]]] = {}
    labels: dict[int, tuple[str, str]] = {}
    label_names: set[str] = set()
    subroutines: dict[int, str] = {}

    for _start, _end, group_lines in groups:
        first_line = group_lines[0].strip()
        full_text = "\n".join(group_lines)

        match = RE_INLINE_COMMENT.match(first_line)
        if match:
            addr = int(match.group(1), 16)
            text = match.group(2)
            inline_comments.setdefault(addr, []).append(
                (text, group_lines[0].rstrip())
            )
            continue

        match = RE_LABEL.match(first_line)
        if match:
            addr = int(match.group(1), 16)
            name = match.group(2)
            labels[addr] = (name, group_lines[0].rstrip())
            label_names.add(name)
            continue

        match = RE_SUBROUTINE.match(first_line)
        if match:
            addr = int(match.group(1), 16)
            subroutines[addr] = full_text

    return inline_comments, labels, label_names, subroutines


def translate_address_in_text(text: str, old_addr: int, new_addr: int) -> str:
    """Replace ``0xOLDADDR`` with ``0xNEWADDR`` everywhere in ``text``."""
    return text.replace(f"0x{old_addr:04X}", f"0x{new_addr:04X}")


def translate_subroutine(full_text: str, old_addr: int, new_addr: int) -> str:
    """Translate the address argument in a ``subroutine()`` call.

    Only replaces the *first* occurrence of ``0xOLDADDR``: the address
    argument. Description text further inside the call is left
    untouched.
    """
    return full_text.replace(f"0x{old_addr:04X}", f"0x{new_addr:04X}", 1)


__all__ = [
    "RE_INLINE_COMMENT",
    "RE_LABEL",
    "RE_SUBROUTINE",
    "build_confidence_map",
    "build_confidence_map_for_block",
    "group_logical_statements",
    "parse_annotations",
    "translate_address_in_text",
    "translate_subroutine",
]
