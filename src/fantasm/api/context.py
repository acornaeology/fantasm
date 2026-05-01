"""Per-subroutine context computations.

Used when generating the inline-comment workflow input: extracts each
candidate subroutine's metadata, callers, callees, comment density,
and depth in the call graph (leaves first).

Sibling ``disasm_tools.context`` mixed pure logic with file IO and
project-specific summary text. The fantasm port lifts the pure
helper :func:`compute_call_depths` into the API; the file-IO
``generate_context`` will land alongside the ``fantasm context``
Click sub-command.
"""

from __future__ import annotations

import networkx as nx


def compute_call_depths(graph: nx.DiGraph) -> dict[str, int]:
    """Return ``{node_id -> depth}`` over the internal subgraph.

    Depth 0 is a leaf (no internal callees). Depth ``N`` is one more
    than the maximum depth of its callees. Cycles are collapsed via
    strongly-connected-component condensation so a cycle's nodes all
    share the same depth.

    Only internal nodes (``external=False``) are included.
    """
    internal = {n for n in graph.nodes if not graph.nodes[n].get("external")}
    subgraph = graph.subgraph(internal).copy()

    if nx.is_directed_acyclic_graph(subgraph):
        depths: dict[str, int] = {}
        for node in reversed(list(nx.topological_sort(subgraph))):
            successors = list(subgraph.successors(node))
            depths[node] = (
                1 + max(depths[s] for s in successors) if successors else 0
            )
        return depths

    condensation = nx.condensation(subgraph)
    mapping = condensation.graph["mapping"]
    scc_depths: dict[int, int] = {}
    for scc_node in reversed(list(nx.topological_sort(condensation))):
        successors = list(condensation.successors(scc_node))
        scc_depths[scc_node] = (
            1 + max(scc_depths[s] for s in successors) if successors else 0
        )
    return {node: scc_depths[mapping[node]] for node in internal}


__all__ = ["compute_call_depths"]
