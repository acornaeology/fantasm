"""Lint disassembly driver scripts and project documentation.

Pure-logic helpers for validating that:

1. Annotation addresses (``comment``/``subroutine``/``label``) in a
   driver script correspond to addresses the disassembler actually
   emitted.
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

from .driver_annotations import parse_driver_annotations


def extract_annotations(driver_text: str) -> list[dict]:
    """Extract all annotation addresses from driver-script text.

    Recognises ``comment``, ``subroutine`` and ``label`` calls in both
    the py8dis (bare function) and dasmos (``d.<method>``) dialects,
    including calls that span several lines, via
    :func:`~fantasm.api.driver_annotations.parse_driver_annotations`.
    Calls whose address isn't a literal are skipped. Returns dicts
    with keys ``kind``, ``address``, ``line_number`` (1-based, of the
    opening line), ``detail``, and ``name`` (``None`` for comments,
    or when the name isn't a string literal).

    For ``subroutine`` calls, ``detail`` is ``"entry_point"`` unless
    the call passes ``is_entry_point=False``, in which case it is
    ``"metadata_only"`` (the call is documentation-only and the
    address shouldn't be expected to appear in the disassembler
    output).

    Raises :class:`~fantasm.api.driver_annotations.DriverParseError`
    when the script is not valid Python.
    """
    annotations: list[dict] = []
    for annotation in parse_driver_annotations(driver_text):
        detail: str | None = None
        if annotation.kind == "subroutine":
            detail = (
                "entry_point" if annotation.is_entry_point else "metadata_only"
            )
        annotations.append(
            {
                "kind": annotation.kind,
                "address": annotation.address,
                "line_number": annotation.line_number,
                "detail": detail,
                "name": annotation.name,
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


def valid_label_names_from_data(data: dict) -> set[str]:
    """Return every label name the disassembly defines, for validating
    ``label:NAME`` references.

    Mirrors the site generator's ``build_label_addrs`` name set so a
    ``label:`` the linter accepts is exactly one the generator can
    resolve: item labels, item sub-labels, subroutine names, memory-map
    and index-base names, and external-label names.
    """
    names: set[str] = set()
    for entry in data.get("memory_map", []):
        if entry.get("name"):
            names.add(entry["name"])
    for entry in data.get("index_bases", []):
        if entry.get("name"):
            names.add(entry["name"])
    for sub in data.get("subroutines", []):
        if sub.get("name"):
            names.add(sub["name"])
    ext = data.get("external_labels") or {}
    if isinstance(ext, dict):
        names.update(ext)
    for item in data.get("items", []):
        names.update(item.get("labels", []))
        for sub_names in item.get("sub_labels", {}).values():
            names.update(sub_names)
    return names


_GLOSSARY_HEADING_RE = re.compile(r"^\*\*(.+?)\*\*(?:\s*\((.+?)\))?\s*$", re.M)


def _slugify(text: str) -> str:
    """URL-friendly slug — must match the site generator's ``_slugify``."""
    return re.sub(r"[^a-z0-9-]", "", text.lower().replace(" ", "-"))


def glossary_slugs_from_markdown(md_text: str) -> set[str]:
    """Parse ``GLOSSARY.md`` and return the set of term slugs, for
    validating ``glossary:SLUG`` references."""
    return {
        _slugify(m.group(1)) for m in _GLOSSARY_HEADING_RE.finditer(md_text)
    }


# Inline scheme links in Markdown / driver comment text:
# ``](label:NAME[@version][?flag])`` and ``](glossary:SLUG)``.
_INLINE_SCHEME_LINK_RE = re.compile(r"\]\((label|glossary):([^)\s]+)\)")


def find_inline_scheme_links(text: str) -> list[dict]:
    """Extract every inline ``label:`` / ``glossary:`` link in ``text``.

    Each result is ``{"scheme", "target", "name", "line_number"}`` where
    ``name`` is the bare label name (``@version`` / ``?flag`` stripped)
    for a ``label:`` link, or the lower-cased slug for a ``glossary:``
    link.
    """
    results: list[dict] = []
    for m in _INLINE_SCHEME_LINK_RE.finditer(text):
        scheme, target = m.group(1), m.group(2)
        if scheme == "label":
            name = re.split(r"[@?]", target, maxsplit=1)[0]
        else:
            name = target.lower()
        line_number = text.count("\n", 0, m.start()) + 1
        results.append({
            "scheme": scheme,
            "target": target,
            "name": name,
            "line_number": line_number,
        })
    return results


def address_ranges_from_data(
    data: dict,
    *,
    base_regions: Iterable[tuple[int, int]] = (),
    rom_base_default: int = 0x8000,
    rom_size_default: int = 0x2000,
    block_padding: int = 32,
    last_block_padding: int = 16,
    block_gap_threshold: int = 256,
) -> list[tuple[int, int]]:
    """Build address ranges covered by the disassembly.

    Returns ``(start, end)`` inclusive tuples. Components, in order:

    - ``base_regions`` (workspace + hardware/OS regions, typically
      derived from
      :meth:`~fantasm.api.version_graph.VersionGraph.effective_regions`
      ∪ :meth:`~fantasm.api.version_graph.VersionGraph.effective_external_regions`);
    - the full ROM range from JSON metadata;
    - relocated-code clusters: addresses outside the ROM range are
      grouped into contiguous blocks (gaps larger than
      ``block_gap_threshold`` start a new block) and padded out by
      ``block_padding`` to cover data tails within relocated blocks.

    ``rom_base_default`` / ``rom_size_default`` are fallbacks for
    when the JSON metadata lacks ``load_addr`` / ``end_addr`` (BBC
    8K sideways-ROM defaults; pass different values for 16K ADFS,
    32K-bank carts, etc.).
    """
    item_addrs = sorted(item["addr"] for item in data["items"])
    if not item_addrs:
        return list(base_regions)

    meta = data.get("meta", {})
    load_addr = meta.get("load_addr", rom_base_default)
    end_addr = meta.get("end_addr", load_addr + rom_size_default)
    ranges: list[tuple[int, int]] = list(base_regions)
    ranges.append((load_addr, end_addr - 1))

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
    base_regions: Iterable[tuple[int, int]] = (),
    rom_base_default: int = 0x8000,
    rom_size_default: int = 0x2000,
) -> list[tuple[int, int]]:
    """File-IO wrapper around :func:`address_ranges_from_data`."""
    return address_ranges_from_data(
        json.loads(Path(json_filepath).read_text()),
        base_regions=base_regions,
        rom_base_default=rom_base_default,
        rom_size_default=rom_size_default,
    )


__all__ = [
    "address_in_ranges",
    "address_ranges_from_data",
    "extract_annotations",
    "find_code_block_ranges",
    "find_inline_scheme_links",
    "find_nth_occurrence",
    "glossary_slugs_from_markdown",
    "load_address_ranges",
    "load_valid_addresses",
    "offset_in_code_block",
    "valid_addresses_from_data",
    "valid_label_names_from_data",
]
