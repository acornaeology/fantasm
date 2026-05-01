"""Find labels worth promoting to entry points or subroutines.

Scores every labelled code item by combining four signals:

- whether the predecessor item is a terminating mnemonic or
  data-separated (no fall-through path);
- in-degree (how many JSR / branch references reach the label);
- whether those references are calls (JSR/JMP) or branches;
- come-from distance (how far the call sites are).

Higher scores are stronger candidates for promoting to ``entry()``
or ``subroutine()`` declarations.

ADFS and EBR shipped this module identically; NFS and TUBE didn't
have it. The fantasm port lifts the pure analysis function out of
the file-IO + print wrapper so it's testable directly on a JSON
data dict.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path


# Mnemonics that unconditionally terminate control flow.
TERMINAL_MNEMONICS: frozenset[str] = frozenset({"rts", "jmp", "brk", "rti"})

# Call mnemonics (as opposed to branches).
CALL_MNEMONICS: frozenset[str] = frozenset({"jsr", "jmp"})


def analyze_labels(data: dict) -> list[dict]:
    """Score every labelled code item in ``data`` for promotion.

    Returns a list of dicts (sorted by descending score, then by
    address) with keys: ``addr``, ``name``, ``score``, ``total_refs``,
    ``jsr_refs``, ``branch_refs``, ``max_distance``,
    ``mean_distance``, ``after_terminal``, ``is_entry``,
    ``is_subroutine``.
    """
    items = data["items"]
    sub_addrs = {s["addr"] for s in data.get("subroutines", [])}

    code_items = sorted(
        [i for i in items if i.get("type") == "code"],
        key=lambda i: i["addr"],
    )

    prev_map: dict[int, dict] = {}
    for i in range(1, len(code_items)):
        prev_map[code_items[i]["addr"]] = code_items[i - 1]

    # Addresses where a labelled code item is preceded by data within
    # 20 items — there's no fall-through, regardless of the previous
    # mnemonic.
    data_separated: set[int] = set()
    all_items_sorted = sorted(items, key=lambda i: i["addr"])
    for i, item in enumerate(all_items_sorted):
        if item.get("type") != "code" or not item.get("labels"):
            continue
        for j in range(i - 1, max(i - 20, -1), -1):
            prev_item = all_items_sorted[j]
            if prev_item.get("type") == "code":
                break
            if prev_item.get("type") in ("byte", "string", "word"):
                data_separated.add(item["addr"])
                break

    # Items previously declared as entry points (py8dis emits a
    # "*****" comment-before banner for them).
    entry_addrs: set[int] = set()
    for item in items:
        for cb in item.get("comments_before", []):
            if cb.startswith("*****"):
                entry_addrs.add(item["addr"])
                break

    ref_sources: dict[int, list[dict]] = {}
    for item in code_items:
        target = item.get("target")
        if target and target != item["addr"]:
            ref_sources.setdefault(target, []).append(item)

    candidates: list[dict] = []
    for item in code_items:
        labels = item.get("labels", [])
        if not labels:
            continue

        addr = item["addr"]
        name = labels[0]
        is_subroutine = addr in sub_addrs
        is_entry = addr in entry_addrs

        prev = prev_map.get(addr)
        after_terminal = (
            addr in data_separated
            or (prev is not None and prev.get("mnemonic") in TERMINAL_MNEMONICS)
        )

        sources = ref_sources.get(addr, [])
        refs_from_json = item.get("references", [])

        jsr_refs = sum(
            1 for s in sources if s.get("mnemonic") in CALL_MNEMONICS
        )
        branch_refs = len(sources) - jsr_refs
        total_refs = len(sources)

        extra_refs = len(refs_from_json) - total_refs
        if extra_refs > 0:
            total_refs += extra_refs

        distances = [abs(s["addr"] - addr) for s in sources]
        if refs_from_json:
            distances.extend(abs(r - addr) for r in refs_from_json)
        distances = sorted(set(distances))

        max_distance = max(distances) if distances else 0
        mean_distance = (
            sum(distances) / len(distances) if distances else 0.0
        )

        score = 0.0

        # Definite-promotion shortcut: not reachable by fall-through
        # AND independently called from 3+ sites (or 2+ with at least
        # one JSR) is a routine, period.
        if after_terminal and (
            total_refs >= 3 or (total_refs >= 2 and jsr_refs >= 1)
        ):
            score += 50

        if after_terminal:
            score += 20

        score += total_refs * 3
        score += jsr_refs * 5
        score += min(20, max_distance // 0x100)
        score += min(10, int(mean_distance) // 0x200)

        candidates.append(
            {
                "addr": addr,
                "name": name,
                "score": score,
                "total_refs": total_refs,
                "jsr_refs": jsr_refs,
                "branch_refs": branch_refs,
                "max_distance": max_distance,
                "mean_distance": int(mean_distance),
                "after_terminal": after_terminal,
                "is_entry": is_entry,
                "is_subroutine": is_subroutine,
            }
        )

    candidates.sort(key=lambda c: (-c["score"], c["addr"]))
    return candidates


def load_and_analyze_labels(json_filepath: str | Path) -> list[dict]:
    """File-IO wrapper around :func:`analyze_labels`."""
    return analyze_labels(json.loads(Path(json_filepath).read_text()))


__all__ = [
    "CALL_MNEMONICS",
    "TERMINAL_MNEMONICS",
    "analyze_labels",
    "load_and_analyze_labels",
]
