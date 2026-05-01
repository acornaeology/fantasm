"""Lint disassembly driver scripts and project documentation.

Pure-logic helpers for validating that:

1. Annotation addresses (``comment``/``subroutine``/``label``) in a
   driver script correspond to addresses that py8dis actually emitted.
2. Doc addresses cited from ``rom.json`` ``address_links`` map to a
   covered range.
3. Glossary links resolve.
4. Generated assembly contains no double-comment lines.

NFS was the most capable fork (555 lines vs. 522 / 522 / 492). The
fantasm port takes NFS as the base **but adopts ADFS's annotation
regex**, which captures the subroutine name as well as its address —
strictly more information for downstream callers. NFS's richer
docstrings are preserved.

Defaults that were per-project hardcodes in the sibling code (e.g.
``+0x2000`` ROM size) become parameters so a single fantasm install
serves projects with different bank sizes.

The presentational ``lint_*`` and top-level ``lint()`` entry are
deferred to CLI integration.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from pathlib import Path


_COMMENT_HEAD_RE = re.compile(r"comment\(\s*(0x[0-9A-Fa-f]+)")
_SUBROUTINE_HEAD_RE = re.compile(r"subroutine\(\s*(0x[0-9A-Fa-f]+)")
_LABEL_HEAD_RE = re.compile(r"label\(\s*(0x[0-9A-Fa-f]+)")

# Within an accumulated multi-line call, find the second positional
# argument (the name string). \s spans newlines so multi-line calls
# work without further glue.
_NAME_FROM_CALL_RE = re.compile(
    r'^[a-z]+\(\s*0x[0-9A-Fa-f]+\s*,\s*"([^"]*)"'
)


def _accumulate_call(lines: Sequence[str], start_index: int) -> str:
    """Concatenate lines starting at ``start_index`` until parens balance."""
    call_text = lines[start_index]
    paren_depth = call_text.count("(") - call_text.count(")")
    j = start_index + 1
    while paren_depth > 0 and j < len(lines):
        call_text += "\n" + lines[j]
        paren_depth += lines[j].count("(") - lines[j].count(")")
        j += 1
    return call_text


def _extract_name(call_text: str) -> str | None:
    """Extract the positional ``name`` argument from an accumulated call."""
    match = _NAME_FROM_CALL_RE.match(call_text.lstrip())
    return match.group(1) if match else None


def extract_annotations(driver_text: str) -> list[dict]:
    """Extract all annotation addresses from driver-script text.

    Recognises ``comment(0xADDR, ...)``, ``subroutine(0xADDR, ...)``,
    and ``label(0xADDR, ...)`` calls — including calls that wrap
    onto multiple lines (the function walks forward until parens
    balance). Returns dicts with keys ``kind``, ``address``,
    ``line_number`` (1-based, of the opening line), ``detail``, and
    ``name`` (``None`` when the call uses kwargs only or wraps in a
    way that hides the name).

    For ``subroutine`` calls, ``detail`` is ``"entry_point"`` unless
    the full call (across continuation lines) contains
    ``is_entry_point=False``, in which case it is ``"metadata_only"``
    (the call is documentation-only and the address shouldn't be
    expected to appear in py8dis output).
    """
    lines = driver_text.splitlines()
    annotations: list[dict] = []

    for index, line in enumerate(lines):
        stripped = line.lstrip()
        line_number = index + 1

        match = _COMMENT_HEAD_RE.match(stripped)
        if match:
            annotations.append(
                {
                    "kind": "comment",
                    "address": int(match.group(1), 16),
                    "line_number": line_number,
                    "detail": None,
                    "name": None,
                }
            )
            continue

        match = _SUBROUTINE_HEAD_RE.match(stripped)
        if match:
            call_text = _accumulate_call(lines, index)
            is_entry_point = "is_entry_point=False" not in call_text
            annotations.append(
                {
                    "kind": "subroutine",
                    "address": int(match.group(1), 16),
                    "line_number": line_number,
                    "detail": "entry_point" if is_entry_point else "metadata_only",
                    "name": _extract_name(call_text),
                }
            )
            continue

        match = _LABEL_HEAD_RE.match(stripped)
        if match:
            call_text = _accumulate_call(lines, index)
            annotations.append(
                {
                    "kind": "label",
                    "address": int(match.group(1), 16),
                    "line_number": line_number,
                    "detail": None,
                    "name": _extract_name(call_text),
                }
            )

    return annotations


def valid_addresses_from_data(data: dict) -> set[int]:
    """Return the set of valid addresses derived from disassembly JSON.

    Combines item addresses, sub-label addresses, external-label
    addresses, subroutine addresses, and the full ROM range (so labels
    at ``move()`` source addresses are accepted).
    """
    addresses: set[int] = {item["addr"] for item in data["items"]}
    for item in data["items"]:
        for addr_str in item.get("sub_labels", {}):
            addresses.add(int(addr_str))
    for addr in data.get("external_labels", {}).values():
        addresses.add(addr)
    for sub in data.get("subroutines", []):
        addresses.add(sub["addr"])
    load_addr = data["meta"]["load_addr"]
    end_addr = data["meta"]["end_addr"]
    addresses.update(range(load_addr, end_addr))
    return addresses


def address_ranges_from_data(
    data: dict,
    *,
    rom_base_default: int = 0x8000,
    rom_size_default: int = 0x2000,
    block_padding: int = 32,
    last_block_padding: int = 16,
    block_gap_threshold: int = 256,
) -> list[tuple[int, int]]:
    """Build address ranges covered by the disassembly.

    Returns ``(start, end)`` inclusive tuples. The full ROM range is
    always included; relocated-code addresses outside the ROM range
    are grouped into contiguous blocks (gaps larger than
    ``block_gap_threshold`` start a new block) and padded out by
    ``block_padding`` to cover data tails within relocated blocks.

    The defaults match the BBC sideways-ROM 8K convention; pass
    different ``rom_base_default`` / ``rom_size_default`` for projects
    with different bank sizes (16K ADFS, 32K-bank carts, etc.).
    External labels are intentionally excluded — they name operand
    targets (workspace variables) but don't produce assembly items
    that the website's anchors can target.
    """
    item_addrs = sorted(item["addr"] for item in data["items"])
    if not item_addrs:
        return []

    meta = data.get("meta", {})
    load_addr = meta.get("load_addr", rom_base_default)
    end_addr = meta.get("end_addr", load_addr + rom_size_default)
    ranges: list[tuple[int, int]] = [(load_addr, end_addr - 1)]

    extra: set[int] = set()
    for addr in item_addrs:
        if addr < load_addr or addr >= end_addr:
            extra.add(addr)
    for sub in data.get("subroutines", []):
        extra.add(sub["addr"])

    sorted_extra = sorted(extra)
    if sorted_extra:
        block_start = sorted_extra[0]
        block_end = sorted_extra[0]
        for addr in sorted_extra[1:]:
            if addr - block_end > block_gap_threshold:
                ranges.append((block_start, block_end + block_padding))
                block_start = addr
            block_end = addr
        ranges.append((block_start, block_end + last_block_padding))

    return ranges


def address_in_ranges(
    address: int, ranges: Iterable[tuple[int, int]]
) -> bool:
    """``True`` iff ``address`` falls within any inclusive ``(start, end)`` range."""
    return any(start <= address <= end for start, end in ranges)


def find_code_block_ranges(md_text: str) -> list[tuple[int, int]]:
    """Find character offsets of fenced code blocks in Markdown.

    Returns inclusive ``(start, end)`` character offsets covering each
    fenced block from its opening fence to its closing one. Recognises
    both ``\\`\\`\\`` and ``~~~`` fences.
    """
    ranges: list[tuple[int, int]] = []
    in_block = False
    block_start = 0
    offset = 0
    for line in md_text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            if not in_block:
                block_start = offset
                in_block = True
            else:
                ranges.append((block_start, offset + len(line)))
                in_block = False
        offset += len(line)
    return ranges


def offset_in_code_block(
    offset: int, code_block_ranges: Iterable[tuple[int, int]]
) -> bool:
    """``True`` iff ``offset`` falls inside any fenced code block."""
    return any(start <= offset < end for start, end in code_block_ranges)


def find_nth_occurrence(text: str, pattern: str, n: int) -> int:
    """Find the character offset of the ``n``-th (0-based) occurrence of ``pattern``.

    Returns ``-1`` if ``pattern`` does not occur ``n + 1`` times.
    """
    start = 0
    for _ in range(n + 1):
        index = text.find(pattern, start)
        if index < 0:
            return -1
        start = index + 1
    return index


# --- File-IO wrappers (thin) ---------------------------------------


def load_valid_addresses(json_filepath: str | Path) -> set[int]:
    """File-IO wrapper around :func:`valid_addresses_from_data`."""
    return valid_addresses_from_data(
        json.loads(Path(json_filepath).read_text())
    )


def load_address_ranges(
    json_filepath: str | Path,
    *,
    rom_base_default: int = 0x8000,
    rom_size_default: int = 0x2000,
) -> list[tuple[int, int]]:
    """File-IO wrapper around :func:`address_ranges_from_data`."""
    return address_ranges_from_data(
        json.loads(Path(json_filepath).read_text()),
        rom_base_default=rom_base_default,
        rom_size_default=rom_size_default,
    )


__all__ = [
    "address_in_ranges",
    "address_ranges_from_data",
    "extract_annotations",
    "find_code_block_ranges",
    "find_nth_occurrence",
    "load_address_ranges",
    "load_valid_addresses",
    "offset_in_code_block",
    "valid_addresses_from_data",
]
