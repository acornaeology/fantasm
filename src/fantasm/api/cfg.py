"""Inter-procedural call-graph construction.

Builds a :class:`networkx.DiGraph` whose nodes are subroutines and
whose edges represent JSR (call) and JMP (tail-call) relationships.

The sibling ``disasm_tools.cfg`` carried a hardcoded
``MEMORY_REGIONS`` constant including the NFS-specific ROM range
``0x8000-0x9FFF``. The fantasm port reuses
:func:`fantasm.api.audit.build_memory_regions`, which derives the ROM
range from the disassembly's JSON metadata — so projects with
different ROM bank sizes get correct extents without special-casing.

The presentational ``format_*`` and top-level ``cfg()`` entry from
the sibling code are deferred to CLI integration.
"""

from __future__ import annotations

import bisect
import json
from pathlib import Path

import networkx as nx

from .audit import build_memory_regions, region_for_addr


def build_call_graph(json_filepath: str | Path) -> nx.DiGraph:
    """Build a call-graph DiGraph from a py8dis JSON output.

    Nodes (keyed by ``"0xNNNN"``) represent ROM subroutines and
    external OS entry points. Edges carry ``call_sites`` (sorted list
    of caller addresses) and ``type`` (``"jsr"`` or ``"jmp"``).
    """
    data = json.loads(Path(json_filepath).read_text())
    items = data["items"]
    raw_subs = data.get("subroutines", [])
    external_labels = data.get("external_labels", {})
    memory_regions = build_memory_regions(data.get("meta", {}))

    addr_to_sub = {s["addr"]: s for s in raw_subs}
    ext_addr_to_name = {v: k for k, v in external_labels.items()}

    rom_subs = sorted(
        [s for s in raw_subs if s["addr"] < 0xFF00],
        key=lambda s: s["addr"],
    )

    sub_extents: dict[int, tuple[int, int | None]] = {}
    for idx, sub in enumerate(rom_subs):
        sub_addr = sub["addr"]
        sub_region = region_for_addr(sub_addr, memory_regions)
        extent_end: int | None = None
        for j in range(idx + 1, len(rom_subs)):
            if region_for_addr(rom_subs[j]["addr"], memory_regions) == sub_region:
                extent_end = rom_subs[j]["addr"]
                break
        sub_extents[sub_addr] = (sub_addr, extent_end)

    rom_sub_addrs = [s["addr"] for s in rom_subs]

    def containing_sub_addr(item_addr: int) -> int | None:
        idx = bisect.bisect_right(rom_sub_addrs, item_addr) - 1
        if idx < 0:
            return None
        sub_addr = rom_sub_addrs[idx]
        if region_for_addr(item_addr, memory_regions) != region_for_addr(
            sub_addr, memory_regions
        ):
            return None
        _, extent_end = sub_extents[sub_addr]
        if extent_end is not None and item_addr >= extent_end:
            return None
        return sub_addr

    graph: nx.DiGraph = nx.DiGraph()

    for sub in rom_subs:
        graph.add_node(
            f"0x{sub['addr']:04X}",
            name=sub.get("name", f"sub_c{sub['addr']:04x}"),
            title=sub.get("title", ""),
            external=False,
        )

    edge_data: dict[tuple[str, str], dict] = {}

    for item in items:
        mnemonic = item.get("mnemonic")
        if mnemonic not in ("jsr", "jmp"):
            continue
        target = item.get("target")
        if target is None:
            continue
        source_sub = containing_sub_addr(item["addr"])
        if source_sub is None:
            continue

        source_id = f"0x{source_sub:04X}"

        if target in addr_to_sub:
            target_id = f"0x{target:04X}"
            target_sub = addr_to_sub[target]
            if mnemonic == "jmp" and target_id == source_id:
                continue
            if not graph.has_node(target_id):
                graph.add_node(
                    target_id,
                    name=target_sub.get("name", f"sub_c{target:04x}"),
                    title=target_sub.get("title", ""),
                    external=target >= 0xFF00,
                )
        elif target >= 0xFF00:
            target_id = f"0x{target:04X}"
            if not graph.has_node(target_id):
                name = ext_addr_to_name.get(target, f"os_{target:04x}")
                graph.add_node(target_id, name=name, title="", external=True)
        else:
            continue

        key = (source_id, target_id)
        if key not in edge_data:
            edge_data[key] = {"call_sites": [], "types": set()}
        edge_data[key]["call_sites"].append(f"0x{item['addr']:04X}")
        edge_data[key]["types"].add(mnemonic)

    for (source_id, target_id), edata in edge_data.items():
        edge_type = "jsr" if "jsr" in edata["types"] else "jmp"
        graph.add_edge(
            source_id,
            target_id,
            call_sites=sorted(edata["call_sites"]),
            type=edge_type,
        )

    return graph


def resolve_sub_node(graph: nx.DiGraph, target: str) -> str | None:
    """Resolve a textual target (hex address or name) to a node ID.

    Tries hex address first, then exact name match, then unique
    substring match against node names. Returns ``None`` for unknown
    or ambiguous targets (callers can warn).
    """
    cleaned = target.strip().lstrip("$&").removeprefix("0x")
    try:
        addr = int(cleaned, 16)
        node_id = f"0x{addr:04X}"
        if graph.has_node(node_id):
            return node_id
    except ValueError:
        pass

    for nid in graph.nodes:
        if graph.nodes[nid].get("name") == target:
            return nid

    matches = [
        nid for nid in graph.nodes if target in graph.nodes[nid].get("name", "")
    ]
    if len(matches) == 1:
        return matches[0]
    return None


__all__ = ["build_call_graph", "resolve_sub_node"]
