"""Per-subroutine context computations.

Used by the inline-comment and rename workflows: depth ordering,
calling-convention extraction (entry / call sites / exits / post-call
context), and uncommented-region analysis.

Sibling ``disasm_tools.context`` was the inline-comment workflow's
input generator; ADFS ``tools/sub_context.py`` was a sister script
focused on calling-convention extraction. The fantasm port lifts the
pure-logic surface from both into one module.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import networkx as nx

from .audit import TERMINATING_MNEMONICS
from .asm_extract import build_index


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


# --- Sub calling-convention extraction ---------------------------


@dataclass(frozen=True)
class CallSiteContext:
    """One call site for a target subroutine.

    ``in_sub_name`` and ``in_sub_addr`` identify the calling
    subroutine (when the caller could be located in the call graph).
    ``asm_lines`` is the assembly window around the call, with the
    ``call_line_index`` (relative to ``asm_lines``) marking the call
    instruction itself.
    """

    addr: int
    mnemonic: str  # "jsr" / "jmp"
    in_sub_name: str | None
    in_sub_addr: int | None
    asm_lines: tuple[str, ...]
    call_line_index: int


@dataclass(frozen=True)
class ExitPointContext:
    """One terminating instruction within a subroutine."""

    addr: int
    mnemonic: str  # "rts" / "jmp" / "brk" / "rti"
    asm_lines: tuple[str, ...]
    exit_line_index: int


@dataclass(frozen=True)
class SubContext:
    """Calling-convention context for a single subroutine."""

    addr: int
    name: str
    title: str
    body_lines: tuple[str, ...]
    body_start_line: int  # 0-indexed line of the first body line
    call_sites: tuple[CallSiteContext, ...]
    exit_points: tuple[ExitPointContext, ...]


def extract_sub_context(
    sub: dict,
    asm_lines: Sequence[str],
    call_graph: nx.DiGraph,
    *,
    body_window: int = 20,
    caller_context: int = 3,
    after_context: int = 2,
    exit_context: int = 3,
) -> SubContext:
    """Build a :class:`SubContext` for ``sub``.

    ``sub`` is a single dict from
    :func:`fantasm.api.audit.load_subroutines`. ``asm_lines`` is the
    full assembly file split with ``splitlines(keepends=True)``.
    ``call_graph`` is from :func:`fantasm.api.cfg.build_call_graph`.

    The body window starts at the subroutine's address and extends
    up to ``body_window`` lines (or to the next subroutine, whichever
    comes first). Call sites come from the call graph's predecessors,
    with ``caller_context`` lines before and ``after_context`` lines
    after each. Exit points are every terminating mnemonic within
    the sub's extent, with ``exit_context`` lines before each.
    """
    addr_to_line, _ = build_index(asm_lines)

    sub_addr = sub["addr"]
    sub_line = addr_to_line.get(sub_addr, 0)
    next_sub = sub.get("next_sub")
    if next_sub is not None:
        next_line = addr_to_line.get(next_sub["addr"], len(asm_lines))
    else:
        next_line = len(asm_lines)
    body_end = min(sub_line + body_window, next_line, len(asm_lines))
    body_lines = tuple(asm_lines[sub_line:body_end])

    call_sites: list[CallSiteContext] = []
    sub_node_id = f"0x{sub_addr:04X}"
    if call_graph.has_node(sub_node_id):
        for predecessor_id in call_graph.predecessors(sub_node_id):
            edge = call_graph.edges[predecessor_id, sub_node_id]
            for site_hex in edge.get("call_sites", []):
                try:
                    site_addr = int(site_hex, 16)
                except ValueError:
                    continue
                line_idx = addr_to_line.get(site_addr)
                if line_idx is None:
                    continue
                start = max(0, line_idx - caller_context)
                end = min(len(asm_lines), line_idx + after_context + 1)
                window = tuple(asm_lines[start:end])
                pred_attrs = call_graph.nodes[predecessor_id]
                pred_addr: int | None
                try:
                    pred_addr = int(predecessor_id, 16)
                except ValueError:
                    pred_addr = None
                call_sites.append(
                    CallSiteContext(
                        addr=site_addr,
                        mnemonic=edge.get("type", "jsr"),
                        in_sub_name=pred_attrs.get("name"),
                        in_sub_addr=pred_addr,
                        asm_lines=window,
                        call_line_index=line_idx - start,
                    )
                )
    call_sites.sort(key=lambda c: c.addr)

    exit_points: list[ExitPointContext] = []
    for item in sub.get("items", []):
        if item.get("type") != "code":
            continue
        mnemonic = item.get("mnemonic")
        if mnemonic not in TERMINATING_MNEMONICS:
            continue
        line_idx = addr_to_line.get(item["addr"])
        if line_idx is None:
            continue
        start = max(0, line_idx - exit_context)
        window = tuple(asm_lines[start:line_idx + 1])
        exit_points.append(
            ExitPointContext(
                addr=item["addr"],
                mnemonic=mnemonic,
                asm_lines=window,
                exit_line_index=line_idx - start,
            )
        )

    return SubContext(
        addr=sub_addr,
        name=sub["name"],
        title=sub.get("title", ""),
        body_lines=body_lines,
        body_start_line=sub_line,
        call_sites=tuple(call_sites),
        exit_points=tuple(exit_points),
    )


# --- Uncommented-region analysis ---------------------------------


@dataclass(frozen=True)
class UncommentedSubReport:
    """A subroutine that's a candidate for annotation work.

    Surfaces the subroutine's named callees and any workspace label
    references found within its extent, so the user can infer the
    sub's purpose from its relationships with already-understood
    code.
    """

    addr: int
    name: str
    title: str
    commented: int
    total: int
    density_pct: float
    callees: tuple[str, ...]
    workspace_refs: tuple[str, ...]


def analyse_uncommented_subs(
    audit_subs: Sequence[dict],
    *,
    label_to_name: dict[int, str] | None = None,
    workspace_label_patterns: Sequence[str] = (),
    density_threshold_pct: float = 30.0,
    min_items: int = 20,
) -> list[UncommentedSubReport]:
    """Find subroutines below a comment-density threshold and report context.

    For each subroutine in ``audit_subs`` (typically from
    :func:`fantasm.api.audit.load_subroutines`) with at least
    ``min_items`` code items and inline-comment density below
    ``density_threshold_pct``, returns an
    :class:`UncommentedSubReport` carrying:

    - the named callees (JSR / JMP targets that resolve via
      ``label_to_name``);
    - the workspace label references whose name contains any of the
      ``workspace_label_patterns`` substrings (typically
      ``("wksp_", "fsm_", "zp_", ...)`` for BBC-style projects).

    With no ``workspace_label_patterns``, no label filtering is
    applied and ``workspace_refs`` is empty. ``label_to_name`` maps
    addresses to their canonical names; pass the union of subroutine
    names and external-label names for best resolution.
    """
    name_lookup = label_to_name or {}
    patterns = tuple(workspace_label_patterns)

    results: list[UncommentedSubReport] = []
    for sub in audit_subs:
        code_items = [
            item for item in sub.get("items", [])
            if item.get("type") == "code"
        ]
        total = len(code_items)
        if total < min_items:
            continue
        commented = sum(
            1 for item in code_items if item.get("comment_inline")
        )
        density = 100.0 * commented / total if total else 0.0
        if density >= density_threshold_pct:
            continue

        callees: set[str] = set()
        for item in code_items:
            target = item.get("target")
            mnemonic = item.get("mnemonic")
            if (
                target is not None
                and mnemonic in ("jsr", "jmp")
                and target in name_lookup
            ):
                callees.add(name_lookup[target])

        workspace_refs: set[str] = set()
        if patterns:
            for item in code_items:
                for label in item.get("labels", []):
                    if any(pattern in label for pattern in patterns):
                        workspace_refs.add(label)

        results.append(
            UncommentedSubReport(
                addr=sub["addr"],
                name=sub["name"],
                title=sub.get("title", ""),
                commented=commented,
                total=total,
                density_pct=density,
                callees=tuple(sorted(callees)),
                workspace_refs=tuple(sorted(workspace_refs)),
            )
        )
    return results


__all__ = [
    "CallSiteContext",
    "ExitPointContext",
    "SubContext",
    "UncommentedSubReport",
    "analyse_uncommented_subs",
    "compute_call_depths",
    "extract_sub_context",
]
