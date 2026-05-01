"""Auto-generated-label classification.

Pure-logic helpers for classifying labels emitted by the disassembler
(``c####``, ``l####``, ``loop_c####``, ``sub_c####``) into five
categories: ``subroutine``, ``shared_tail``, ``data``,
``internal_loop``, ``internal_conditional``. These categories drive
the ordered rename workflow.

Sibling ``disasm_tools.labels`` had a single ``generate_labels()``
entry that mixed file IO, printing, and template rendering. The
fantasm port lifts the pure helpers into a stable surface; the
file-writing wrapper will land with the ``fantasm labels`` Click
sub-command.

Names imported elsewhere in the sibling tree (and now re-exported
publicly here):

- :data:`AUTO_LABEL_RE`
- :func:`collect_auto_labels` (was ``_collect_auto_labels``)
- :data:`CATEGORY_ORDER`
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence


AUTO_LABEL_RE = re.compile(
    r"^(c[0-9a-f]+|l[0-9a-f]+|loop_c[0-9a-f]+|sub_c[0-9a-f]+)$"
)


CATEGORY_ORDER: tuple[str, ...] = (
    "subroutine",
    "shared_tail",
    "data",
    "internal_loop",
    "internal_conditional",
)


def collect_auto_labels(items: Iterable[dict]) -> list[tuple[str, int]]:
    """Return ``[(label_name, addr), ...]`` for every auto-generated label.

    Walks ``items``' ``"labels"`` and ``"sub_labels"`` fields and
    keeps anything matching :data:`AUTO_LABEL_RE`.
    """
    results: list[tuple[str, int]] = []
    for item in items:
        for label in item.get("labels", []):
            if AUTO_LABEL_RE.match(label):
                results.append((label, item["addr"]))
        for addr_str, sub_labels in item.get("sub_labels", {}).items():
            for label in sub_labels:
                if AUTO_LABEL_RE.match(label):
                    results.append((label, int(addr_str)))
    return results


def build_target_refs(items: Iterable[dict]) -> dict[int, list[dict]]:
    """Return an ``addr -> referencing items`` index.

    Indexes by each item's ``target`` field (the address of an
    instruction's operand target, when the operand is a code/data
    reference).
    """
    refs: dict[int, list[dict]] = {}
    for item in items:
        target = item.get("target")
        if target is not None:
            refs.setdefault(target, []).append(item)
    return refs


def find_containing_sub_for_addr(
    addr: int,
    sorted_subs: Sequence[dict],
    memory_regions: Sequence[tuple[int, int]],
) -> dict | None:
    """Find the subroutine in the same memory region whose start ≤ addr.

    Unlike :func:`fantasm.api.audit.find_containing_sub`, this variant
    is region-aware: a sub in a different memory region is never
    treated as containing ``addr``.
    """
    from .audit import region_for_addr

    addr_region = region_for_addr(addr, memory_regions)
    result: dict | None = None
    for sub in sorted_subs:
        sub_region = region_for_addr(sub["addr"], memory_regions)
        if sub_region != addr_region:
            continue
        if sub["addr"] <= addr:
            result = sub
        else:
            break
    return result


def classify_labels(
    auto_labels: Iterable[tuple[str, int]],
    items: Sequence[dict],
    target_refs: dict[int, list[dict]],
    audit_subs: Sequence[dict],
    memory_regions: Sequence[tuple[int, int]],
) -> list[dict]:
    """Classify each auto-generated label into a category.

    Returns a list of dicts with keys: ``name``, ``addr``,
    ``category``, ``parent_sub_name``, ``parent_sub_addr``,
    ``inbound_refs`` (each ``{addr, mnemonic, sub_name, sub_addr,
    cross_sub}``), ``cross_sub_count``.
    """
    items_by_addr = {item["addr"]: item for item in items}
    sorted_subs = sorted(audit_subs, key=lambda s: s["addr"])

    results: list[dict] = []
    for label_name, label_addr in auto_labels:
        parent_sub = find_containing_sub_for_addr(
            label_addr, sorted_subs, memory_regions
        )
        parent_name = parent_sub["name"] if parent_sub else None
        parent_addr = parent_sub["addr"] if parent_sub else None

        inbound: list[dict] = []
        for ref_item in target_refs.get(label_addr, []):
            ref_sub = find_containing_sub_for_addr(
                ref_item["addr"], sorted_subs, memory_regions
            )
            ref_sub_name = ref_sub["name"] if ref_sub else "?"
            ref_sub_addr = ref_sub["addr"] if ref_sub else None
            inbound.append(
                {
                    "addr": ref_item["addr"],
                    "mnemonic": ref_item.get("mnemonic", "?"),
                    "sub_name": ref_sub_name,
                    "sub_addr": ref_sub_addr,
                    "cross_sub": ref_sub_addr != parent_addr,
                }
            )

        # Also follow data-reference fields (table/pointer references
        # that don't appear in target_refs).
        item_at_label = items_by_addr.get(label_addr)
        ref_addrs_already = {r["addr"] for r in inbound}
        if item_at_label:
            for ref_addr in item_at_label.get("references", []):
                if ref_addr in ref_addrs_already:
                    continue
                ref_item = items_by_addr.get(ref_addr)
                if not ref_item:
                    continue
                ref_sub = find_containing_sub_for_addr(
                    ref_addr, sorted_subs, memory_regions
                )
                ref_sub_name = ref_sub["name"] if ref_sub else "?"
                ref_sub_addr = ref_sub["addr"] if ref_sub else None
                inbound.append(
                    {
                        "addr": ref_addr,
                        "mnemonic": ref_item.get("mnemonic", "data_ref"),
                        "sub_name": ref_sub_name,
                        "sub_addr": ref_sub_addr,
                        "cross_sub": ref_sub_addr != parent_addr,
                    }
                )

        inbound.sort(key=lambda r: r["addr"])
        cross_sub_refs = [r for r in inbound if r["cross_sub"]]
        has_jsr_jmp = any(
            r["mnemonic"] in ("jsr", "jmp") for r in cross_sub_refs
        )

        # Order matters here: longer prefixes must be checked first
        # so that loop_c… and sub_c… don't accidentally match the
        # shorter c… / l… prefixes.
        if label_name.startswith("sub_c"):
            category = "subroutine"
        elif label_name.startswith("loop_c"):
            category = "internal_loop"
        elif label_name.startswith("l"):
            category = "data"
        elif has_jsr_jmp:
            category = "subroutine"
        elif cross_sub_refs:
            category = "shared_tail"
        else:
            category = "internal_conditional"

        results.append(
            {
                "name": label_name,
                "addr": label_addr,
                "category": category,
                "parent_sub_name": parent_name,
                "parent_sub_addr": parent_addr,
                "inbound_refs": inbound,
                "cross_sub_count": len(cross_sub_refs),
            }
        )

    return results


def sort_labels(classified: Sequence[dict]) -> list[dict]:
    """Sort by category order, then parent-sub address, then label address."""
    cat_idx = {cat: i for i, cat in enumerate(CATEGORY_ORDER)}
    return sorted(
        classified,
        key=lambda r: (
            cat_idx.get(r["category"], 99),
            r["parent_sub_addr"] or 0,
            r["addr"],
        ),
    )


__all__ = [
    "AUTO_LABEL_RE",
    "CATEGORY_ORDER",
    "build_target_refs",
    "classify_labels",
    "collect_auto_labels",
    "find_containing_sub_for_addr",
    "sort_labels",
]
