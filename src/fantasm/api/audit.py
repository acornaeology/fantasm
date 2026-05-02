"""Audit subroutine annotations in a ROM disassembly.

Pure-logic helpers and data-loading routines, factored out of the
sibling ``disasm_tools.audit``. Loads the JSON output from a
disassembly run and computes per-subroutine extents, termination
analysis, entry references, escaping branches, and a flag set
describing potential issues.

The presentational ``format_*`` and top-level ``audit()`` entry from
the sibling code are intentionally not yet ported — they print
directly to stdout, which is a CLI concern. They will land alongside
the ``fantasm audit`` Click sub-command.

Region awareness is project-aware: callers pass a version's
``memory_regions`` (typically derived from
:func:`fantasm.api.version_graph.VersionGraph.effective_regions` plus
the ROM range from JSON metadata). When omitted, the default is the
ROM range alone — sub extents are bounded by ROM only. The earlier
hardcoded BBC ranges that the sibling code carried have been removed.

``TERMINATING_MNEMONICS`` and ``BRANCH_MNEMONICS`` are 6502 facts;
this module imports them from :mod:`fantasm.api.mos6502` (the
canonical home) and uses them internally.
"""

from __future__ import annotations

import json
import re
import warnings
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from .mos6502 import BRANCH_MNEMONICS, TERMINATING_MNEMONICS

ALL_FLAGS: tuple[str, ...] = (
    "FALL_THROUGH",
    "FALL_THROUGH_ENTRY",
    "NO_REFS",
    "BRANCH_ESCAPE",
    "DATA_ONLY",
    "AUTO_NAME",
    "NO_DESCRIPTION",
)


def build_memory_regions(
    meta: dict,
    base_regions: Iterable[tuple[int, int]] = (),
) -> list[tuple[int, int]]:
    """Build the full memory-region list for a single version.

    Appends the ROM region (``meta["load_addr"]`` to
    ``meta["end_addr"] - 1``) onto ``base_regions``. ``base_regions``
    typically comes from
    :meth:`fantasm.api.version_graph.VersionGraph.effective_regions`,
    converted from :class:`Region` dataclasses to ``(start, end)``
    tuples. Defaults to empty — ROM-only.

    Raises ``KeyError`` if ``load_addr`` or ``end_addr`` are missing
    from ``meta``.
    """
    load_addr = meta["load_addr"]
    end_addr = meta["end_addr"] - 1
    return list(base_regions) + [(load_addr, end_addr)]


def region_for_addr(
    addr: int, memory_regions: Sequence[tuple[int, int]]
) -> tuple[int, int] | None:
    """Return the (start, end) region containing ``addr``, or ``None``."""
    for start, end in memory_regions:
        if start <= addr <= end:
            return (start, end)
    return None


def find_containing_sub(
    addr: int, rom_subs: Sequence[dict]
) -> dict | None:
    """Return the last subroutine in ``rom_subs`` whose ``addr <= addr``.

    ``rom_subs`` must be sorted by ``addr`` ascending.
    """
    result: dict | None = None
    for sub in rom_subs:
        if sub["addr"] <= addr:
            result = sub
        else:
            break
    return result


def scan_routine_range(
    addr: int,
    items_by_addr: dict[int, dict],
    sorted_addrs: Sequence[int],
) -> tuple[int | None, int, int, bool]:
    """Walk the items starting at ``addr`` until a terminating mnemonic.

    Returns ``(range_end, code_count, data_count, falls_through)``.
    ``range_end`` is the address of the terminating instruction, or
    ``None`` if the routine falls through without terminating.
    """
    try:
        addr_idx = list(sorted_addrs).index(addr)
    except ValueError:
        return None, 0, 0, True

    code_count = 0
    data_count = 0

    for i in range(addr_idx, len(sorted_addrs)):
        a = sorted_addrs[i]
        item = items_by_addr[a]
        if item.get("type") == "code":
            code_count += 1
        else:
            data_count += 1
        if item.get("mnemonic") in TERMINATING_MNEMONICS:
            return a, code_count, data_count, False

    return None, code_count, data_count, True


def load_subroutines(
    json_filepath: str | Path,
    *,
    memory_regions: Iterable[tuple[int, int]] | None = None,
) -> list[dict]:
    """Load JSON output and compute per-subroutine extents and flags.

    Returns a list of subroutine dicts augmented with: ``items``,
    ``code_count``, ``data_count``, ``last_mnemonic``, ``terminates``,
    ``next_sub``, ``entry_refs``, ``branch_entry_refs``,
    ``escaping_branches``, ``flags``. The ``flags`` entry is a set of
    strings drawn from :data:`ALL_FLAGS`.

    ``memory_regions`` constrains where subroutine extents may run.
    The list should already include both the ROM range and any
    workspace regions where small subs may live. If omitted, it
    defaults to the ROM range alone (derived from the JSON's
    ``meta``) — sub extents are then bounded by ROM only.
    """
    data = json.loads(Path(json_filepath).read_text())
    items = data["items"]
    raw_subs = data.get("subroutines", [])
    if memory_regions is None:
        memory_regions = build_memory_regions(data.get("meta", {}))
    else:
        memory_regions = list(memory_regions)

    rom_subs = [s for s in raw_subs if s["addr"] < 0xFF00]
    rom_subs.sort(key=lambda s: s["addr"])

    items_by_addr = {item["addr"]: item for item in items}
    sorted_items = sorted(items, key=lambda i: i["addr"])

    target_refs: dict[int, list[dict]] = {}
    for item in items:
        target = item.get("target")
        if target is not None:
            target_refs.setdefault(target, []).append(item)

    sub_data: list[dict] = []

    for idx, sub in enumerate(rom_subs):
        sub_addr = sub["addr"]
        sub_region = region_for_addr(sub_addr, memory_regions)

        extent_end: int | None = None
        next_sub_info: dict | None = None
        for j in range(idx + 1, len(rom_subs)):
            candidate = rom_subs[j]
            if region_for_addr(candidate["addr"], memory_regions) == sub_region:
                extent_end = candidate["addr"]
                next_sub_info = {
                    "addr": candidate["addr"],
                    "name": candidate.get("name", "?"),
                }
                break

        sub_items: list[dict] = []
        for item in sorted_items:
            if item["addr"] < sub_addr:
                continue
            if extent_end is not None and item["addr"] >= extent_end:
                break
            if sub_region and region_for_addr(item["addr"], memory_regions) == sub_region:
                sub_items.append(item)
            elif sub_region is None:
                if extent_end is None or item["addr"] < extent_end:
                    sub_items.append(item)

        code_count = sum(1 for i in sub_items if i.get("type") == "code")
        data_count = len(sub_items) - code_count

        code_items = [i for i in sub_items if i.get("type") == "code"]
        last_mnemonic = code_items[-1].get("mnemonic") if code_items else None
        terminates = (
            last_mnemonic in TERMINATING_MNEMONICS if last_mnemonic else False
        )

        item_at_addr = items_by_addr.get(sub_addr)
        has_any_refs = bool(item_at_addr and item_at_addr.get("references"))

        entry_refs: list[dict] = []
        for ref_item in target_refs.get(sub_addr, []):
            if ref_item.get("mnemonic") in ("jsr", "jmp"):
                containing = find_containing_sub(ref_item["addr"], rom_subs)
                ref_sub_name = (
                    containing.get("name", f"&{containing['addr']:04X}")
                    if containing
                    else "?"
                )
                entry_refs.append(
                    {
                        "addr": ref_item["addr"],
                        "mnemonic": ref_item["mnemonic"],
                        "in_sub": ref_sub_name,
                    }
                )

        branch_entry_refs: list[dict] = []
        for ref_item in target_refs.get(sub_addr, []):
            if ref_item.get("mnemonic") in BRANCH_MNEMONICS:
                containing = find_containing_sub(ref_item["addr"], rom_subs)
                ref_sub_name = (
                    containing.get("name", f"&{containing['addr']:04X}")
                    if containing
                    else "?"
                )
                branch_entry_refs.append(
                    {
                        "addr": ref_item["addr"],
                        "mnemonic": ref_item["mnemonic"],
                        "in_sub": ref_sub_name,
                    }
                )

        escaping_branches: list[dict] = []
        for item in sub_items:
            if item.get("mnemonic") in BRANCH_MNEMONICS:
                target = item.get("target")
                if target is not None:
                    in_extent = (
                        (sub_addr <= target < extent_end)
                        if extent_end
                        else (target >= sub_addr)
                    )
                    if not in_extent:
                        escaping_branches.append(
                            {
                                "addr": item["addr"],
                                "mnemonic": item["mnemonic"],
                                "target": target,
                                "target_label": item.get(
                                    "target_label", f"&{target:04X}"
                                ),
                            }
                        )

        sub_data.append(
            {
                "sub": sub,
                "idx": idx,
                "sub_addr": sub_addr,
                "sub_region": sub_region,
                "sub_items": sub_items,
                "code_count": code_count,
                "data_count": data_count,
                "last_mnemonic": last_mnemonic,
                "terminates": terminates,
                "next_sub_info": next_sub_info,
                "has_any_refs": has_any_refs,
                "entry_refs": entry_refs,
                "branch_entry_refs": branch_entry_refs,
                "escaping_branches": escaping_branches,
            }
        )

    results: list[dict] = []
    for i, sd in enumerate(sub_data):
        sub = sd["sub"]
        flags: set[str] = set()

        if not sd["terminates"] and sd["next_sub_info"]:
            flags.add("FALL_THROUGH")

        prev_terminates = True  # default for first sub in region
        if i > 0 and sub_data[i - 1]["sub_region"] == sd["sub_region"]:
            prev_terminates = sub_data[i - 1]["terminates"]

        has_direct_refs = bool(sd["entry_refs"]) or bool(sd["branch_entry_refs"])

        if not has_direct_refs and not sd["has_any_refs"]:
            if not prev_terminates:
                flags.add("FALL_THROUGH_ENTRY")
            else:
                flags.add("NO_REFS")
        elif not has_direct_refs and sd["has_any_refs"]:
            if not prev_terminates:
                flags.add("FALL_THROUGH_ENTRY")

        if sd["escaping_branches"]:
            flags.add("BRANCH_ESCAPE")

        if sd["code_count"] == 0 and sd["data_count"] > 0:
            flags.add("DATA_ONLY")

        name = sub.get("name", "")
        if re.match(r"sub_c[0-9a-f]+$", name):
            flags.add("AUTO_NAME")

        title = sub.get("title", "")
        description = sub.get("description", "")
        if not title and not description:
            flags.add("NO_DESCRIPTION")
        elif len(title) + len(description) < 40 and not description:
            flags.add("NO_DESCRIPTION")

        results.append(
            {
                "addr": sd["sub_addr"],
                "name": name or f"&{sd['sub_addr']:04X}",
                "title": title,
                "description": description,
                "on_entry": sub.get("on_entry", ""),
                "on_exit": sub.get("on_exit", ""),
                "items": sd["sub_items"],
                "code_count": sd["code_count"],
                "data_count": sd["data_count"],
                "last_mnemonic": sd["last_mnemonic"],
                "terminates": sd["terminates"],
                "next_sub": sd["next_sub_info"],
                "entry_refs": sd["entry_refs"],
                "branch_entry_refs": sd["branch_entry_refs"],
                "escaping_branches": sd["escaping_branches"],
                "flags": flags,
            }
        )

    return results


def end_type(sub: dict) -> str:
    """Short string describing how a subroutine ends."""
    if sub["terminates"]:
        return sub["last_mnemonic"].upper()
    if sub["next_sub"]:
        return "FALL→"
    return "END"


def find_sub(subs: Sequence[dict], target: str) -> dict | None:
    """Find a subroutine by hex address or name.

    Tries (1) hex address ``addr_str`` (with $/&/0x prefixes stripped),
    (2) exact name match, (3) substring match on name. When the
    substring match is ambiguous, emits a ``UserWarning`` listing the
    matches and returns ``None``.
    """
    addr_str = target.strip().lstrip("$&").removeprefix("0x")
    try:
        addr = int(addr_str, 16)
        for s in subs:
            if s["addr"] == addr:
                return s
    except ValueError:
        pass

    for s in subs:
        if s["name"] == target:
            return s

    matches = [s for s in subs if target in s["name"]]
    if len(matches) == 1:
        return matches[0]
    if matches:
        names = ", ".join(f"&{m['addr']:04X} {m['name']}" for m in matches)
        warnings.warn(
            f"ambiguous subroutine name {target!r}; matches: {names}",
            stacklevel=2,
        )
    return None


def _parse_addr(target: str) -> int | None:
    """Parse a target string as a hex address. Returns int or None."""
    cleaned = target.strip().lstrip("$&").removeprefix("0x")
    try:
        return int(cleaned, 16)
    except ValueError:
        return None


def find_undeclared_subs(json_filepath: str | Path) -> list[dict]:
    """Find JSR targets that lack ``subroutine()`` declarations.

    Returns a list of dicts with: ``addr``, ``name``, ``range_str``,
    ``code_count``, ``data_count``, ``caller_count``, ``container``.
    """
    data = json.loads(Path(json_filepath).read_text())
    items = data["items"]
    raw_subs = data.get("subroutines", [])

    declared_addrs = {s["addr"] for s in raw_subs}
    rom_subs = sorted(
        [s for s in raw_subs if s["addr"] < 0xFF00],
        key=lambda s: s["addr"],
    )

    items_by_addr = {item["addr"]: item for item in items}
    sorted_addrs = sorted(items_by_addr.keys())

    jsr_caller_counts: dict[int, int] = {}
    for item in items:
        if item.get("mnemonic") == "jsr":
            target = item["target"]
            jsr_caller_counts[target] = jsr_caller_counts.get(target, 0) + 1

    undeclared_addrs = sorted(
        t
        for t in jsr_caller_counts
        if t not in declared_addrs and t in items_by_addr
    )

    results: list[dict] = []
    for addr in undeclared_addrs:
        item = items_by_addr[addr]
        labels = item.get("labels", [])
        name = labels[0] if labels else f"&{addr:04X}"

        range_start = addr
        range_end, code_count, data_count, falls_through = scan_routine_range(
            addr, items_by_addr, sorted_addrs
        )

        if falls_through:
            range_str = f"&{range_start:04X}-FALL→"
        elif range_end is not None:
            range_str = f"&{range_start:04X}-&{range_end:04X}"
        else:
            range_str = f"&{range_start:04X}-?"

        container = find_containing_sub(addr, rom_subs)
        container_name = (
            container.get("name", f"&{container['addr']:04X}")
            if container
            else "?"
        )

        results.append(
            {
                "addr": addr,
                "name": name,
                "range_str": range_str,
                "code_count": code_count,
                "data_count": data_count,
                "caller_count": jsr_caller_counts[addr],
                "container": container_name,
            }
        )

    return results


# --- placeholder-label scanning ---------------------------------------
#
# py8dis auto-discovers routines via code-flow analysis (JSR / branch
# targets) and, when the driver script doesn't declare them, emits
# placeholder names ending in the address in lowercase hex:
#
#   .lXXXX        — pure auto-label (data-flow target)
#   .cXXXX        — pure auto-label (code-flow target)
#   .sub_cXXXX    — auto-discovered subroutine, no driver decl.
#   .loop_cXXXX   — auto-discovered loop entry, no driver decl.
#
# These names are visible in ``output/<ver>.asm`` but never reach the
# JSON's ``subroutines`` list — so the regular subroutine audit can't
# flag them. Project CI needs an independent scan against the asm.

# XXXX is exactly four lowercase hex digits. The optional ``([a-z]+_)``
# prefix tolerates ``sub_`` and ``loop_`` (and anything similar py8dis
# might add) without false-positiving on legitimate semantic names that
# happen to end in hex-looking characters (e.g. ``.spool_tx_succeeded``
# ends in ``ceeded`` — eight chars, not the right shape).
_PLACEHOLDER_LABEL_RE = re.compile(
    r"^\.(?P<prefix>[a-z]+_)?(?P<core>[lc])(?P<addr>[0-9a-f]{4})\s*$"
)

# Known prefixes → human-readable kind.
_PLACEHOLDER_KIND = {
    "": "auto-label",
    "sub_": "sub-placeholder",
    "loop_": "loop-placeholder",
}


@dataclass(frozen=True)
class PlaceholderLabel:
    """A py8dis-auto-discovered routine carrying a hex-tail placeholder.

    These names are visible in ``output/<ver>.asm`` but never reach
    the JSON's declared ``subroutines`` list, so the regular audit
    can't flag them. ``addr`` is parsed from the hex tail of
    ``name``.
    """

    name: str             # without the leading '.'
    addr: int
    kind: str             # one of `_PLACEHOLDER_KIND`'s values
    line_number: int      # 1-based line in the asm file


def find_placeholder_labels(
    asm_lines: Iterable[str],
) -> list[PlaceholderLabel]:
    """Scan asm output for hex-tail placeholder labels.

    Returns the list in line-number order. Each match is one of:

    - ``.lXXXX`` / ``.cXXXX`` — pure auto-label (no prefix)
    - ``.sub_cXXXX``           — auto-discovered subroutine
    - ``.loop_cXXXX``          — auto-discovered loop entry

    where ``XXXX`` is exactly four lowercase hex digits. Any other
    prefix is reported as ``"auto-label"`` (the structural shape is
    the same — only the convention differs).
    """
    results: list[PlaceholderLabel] = []
    for line_number, raw in enumerate(asm_lines, start=1):
        match = _PLACEHOLDER_LABEL_RE.match(raw.rstrip("\r\n"))
        if not match:
            continue
        prefix = match.group("prefix") or ""
        kind = _PLACEHOLDER_KIND.get(prefix, "auto-label")
        results.append(
            PlaceholderLabel(
                name=f"{prefix}{match.group('core')}{match.group('addr')}",
                addr=int(match.group("addr"), 16),
                kind=kind,
                line_number=line_number,
            )
        )
    return results


__all__ = [
    "ALL_FLAGS",
    "PlaceholderLabel",
    "build_memory_regions",
    "end_type",
    "find_containing_sub",
    "find_placeholder_labels",
    "find_sub",
    "find_undeclared_subs",
    "load_subroutines",
    "region_for_addr",
    "scan_routine_range",
]
