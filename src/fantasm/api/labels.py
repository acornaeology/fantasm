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

from .references import reference_addr, reference_addrs, reference_kind


#: The ``ReferenceKind`` value dasmos assigns to an indexing-base access
#: (``lda addr,X`` / ``sta addr,Y`` where the byte touched is ``addr+X``
#: and the base byte itself is never read or written). A label whose
#: references are *exclusively* this kind is a ``d.index_base()``
#: conversion candidate.
INDEXED_KIND = "indexed"

#: The ``ReferenceKind`` value for a plain ``lda addr`` / ``sta addr``.
DIRECT_KIND = "direct"


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
            for ref_addr in reference_addrs(item_at_label.get("references")):
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


# --- Inventory helpers (powering `fantasm labels list` / `refs`) ----


LABEL_SOURCES: tuple[str, ...] = ("driver", "env")


def collect_labels(data: dict) -> list[dict]:
    """Return every label declared in a disassembly, with source tag.

    Walks ``data["items"]``'s ``"labels"`` and ``"sub_labels"`` fields
    (tagged ``source="driver"``) and ``data["external_labels"]``
    (tagged ``source="env"``). Each entry is a dict with keys
    ``name``, ``addr``, ``source``.

    Driver-defined labels are emitted in item / declaration order;
    environment labels follow, in declaration order from the JSON.
    Duplicates are not collapsed — a label that appears as both an
    item label and a sub-label will yield two records. Callers that
    need uniqueness should dedupe on ``(name, addr)``.
    """
    results: list[dict] = []
    for item in data.get("items", []):
        addr = item["addr"]
        for label in item.get("labels", []):
            results.append({"name": label, "addr": addr, "source": "driver"})
        for addr_str, sub_labels in item.get("sub_labels", {}).items():
            sub_addr = int(addr_str)
            for label in sub_labels:
                results.append(
                    {"name": label, "addr": sub_addr, "source": "driver"}
                )
    for name, addr in data.get("external_labels", {}).items():
        results.append({"name": name, "addr": int(addr), "source": "env"})
    return results


def inbound_refs_to(
    addr: int,
    items_by_addr: dict[int, dict],
    target_refs: dict[int, list[dict]],
) -> list[dict]:
    """Return ref-site records pointing at ``addr``.

    Combines two sources:

    * code-flow references — items whose ``target == addr`` (taken
      from ``target_refs``).
    * data references — addresses listed in the ``references`` field
      of the item *at* ``addr`` (table / pointer references the
      disassembler couldn't attribute to a specific instruction).

    Each record carries ``{"addr", "mnemonic", "kind"}``. Code-flow
    refs use the referencing item's mnemonic; data refs use the
    mnemonic of the item at the referencing address when available,
    else ``"data_ref"``. ``kind`` is the dasmos >= 2.0
    ``ReferenceKind`` (``direct`` / ``indexed`` / ``pointer`` / …) of
    the access, joined from the ``references`` field of the item *at*
    ``addr`` by caller address; it is ``None`` for a caller the
    schema-v2 ``references`` field does not classify (including any
    JSON produced by pre-2.0 dasmos, which did not carry kinds).
    Sorted by ``addr``; duplicates (same source addr) are collapsed,
    with the code-flow record taking precedence.
    """
    item_at_addr = items_by_addr.get(addr)
    kind_by_caller: dict[int, str | None] = {}
    if item_at_addr:
        for ref in item_at_addr.get("references") or []:
            kind_by_caller[reference_addr(ref)] = reference_kind(ref)

    seen: dict[int, dict] = {}
    for ref_item in target_refs.get(addr, []):
        seen[ref_item["addr"]] = {
            "addr": ref_item["addr"],
            "mnemonic": ref_item.get("mnemonic", "?"),
            "kind": kind_by_caller.get(ref_item["addr"]),
        }
    if item_at_addr:
        for ref_addr in reference_addrs(item_at_addr.get("references")):
            if ref_addr in seen:
                continue
            ref_item = items_by_addr.get(ref_addr)
            mnemonic = (
                ref_item.get("mnemonic", "data_ref")
                if ref_item
                else "data_ref"
            )
            seen[ref_addr] = {
                "addr": ref_addr,
                "mnemonic": mnemonic,
                "kind": kind_by_caller.get(ref_addr),
            }
    return sorted(seen.values(), key=lambda r: r["addr"])


def label_inventory(data: dict) -> list[dict]:
    """Build the full label inventory for one disassembly.

    Each entry: ``{"name", "addr", "source", "length", "ref_count",
    "refs", "direct_count", "indexed_count", "other_count",
    "is_code", "index_base_only"}``. ``length`` is ``len(name)``.
    ``refs`` is the list returned by :func:`inbound_refs_to` for the
    label's address; ``ref_count`` is its length, broken out so sorts
    / filters don't pay the indexing cost.

    The three per-kind counts split ``refs`` by the dasmos >= 2.0
    ``ReferenceKind`` of each site: ``direct_count`` (plain
    ``lda addr``), ``indexed_count`` (indexing-base ``lda addr,X``),
    and ``other_count`` (every other or unclassified site — pointer
    references, and any site left ``kind == None`` by pre-2.0 JSON).

    ``is_code`` is true when the item *at* the label's address is a
    ``type == "code"`` item — the caveat flag for the
    ``d.index_base()`` workflow, where a genuine code entry point a
    loop happens to read as ``lda entry,X`` must not be moved off the
    memory map. ``index_base_only`` is true when the label has at
    least one reference and *every* one is ``indexed`` — the exact
    ``d.index_base()`` conversion candidate.

    Driver labels are deduped on ``(name, addr)`` (a label can show
    up as both an item label and a sub-label of the parent item);
    env labels are kept as-is.
    """
    items = data.get("items", [])
    items_by_addr = {item["addr"]: item for item in items}
    target_refs = build_target_refs(items)

    ref_cache: dict[int, list[dict]] = {}

    def refs_for(addr: int) -> list[dict]:
        if addr not in ref_cache:
            ref_cache[addr] = inbound_refs_to(
                addr, items_by_addr, target_refs
            )
        return ref_cache[addr]

    seen_driver: set[tuple[str, int]] = set()
    results: list[dict] = []
    for entry in collect_labels(data):
        if entry["source"] == "driver":
            key = (entry["name"], entry["addr"])
            if key in seen_driver:
                continue
            seen_driver.add(key)
        refs = refs_for(entry["addr"])
        kinds = [r["kind"] for r in refs]
        direct_count = sum(1 for k in kinds if k == DIRECT_KIND)
        indexed_count = sum(1 for k in kinds if k == INDEXED_KIND)
        item = items_by_addr.get(entry["addr"])
        results.append(
            {
                "name": entry["name"],
                "addr": entry["addr"],
                "source": entry["source"],
                "length": len(entry["name"]),
                "ref_count": len(refs),
                "refs": refs,
                "direct_count": direct_count,
                "indexed_count": indexed_count,
                "other_count": len(kinds) - direct_count - indexed_count,
                "is_code": bool(item) and item.get("type") == "code",
                "index_base_only": bool(kinds)
                and all(k == INDEXED_KIND for k in kinds),
            }
        )
    return results


__all__ = [
    "AUTO_LABEL_RE",
    "CATEGORY_ORDER",
    "DIRECT_KIND",
    "INDEXED_KIND",
    "LABEL_SOURCES",
    "build_target_refs",
    "classify_labels",
    "collect_auto_labels",
    "collect_labels",
    "find_containing_sub_for_addr",
    "inbound_refs_to",
    "label_inventory",
    "sort_labels",
]
