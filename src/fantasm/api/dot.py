"""Graphviz / GraphML rendering for call graphs and basic-block CFGs.

Pure-Python emission, no ``pydot`` dependency. The call graph is
already a :class:`networkx.DiGraph` (see :mod:`fantasm.api.cfg`); a
basic-block CFG is built on demand from the :func:`find_basic_blocks`
output. GraphML uses :func:`networkx.generate_graphml`.

Output is designed for the ``dot`` layout engine — left-to-right for
the call graph, top-to-bottom for per-routine CFGs. The
:func:`render_dot` helper shells out to the ``dot`` binary when it is
on ``PATH``.

Styling vocabulary (cribbed from OWL BASIC's CFG visualiser and the
Solarized palette):

- Hexagon: subroutine entry / root (call graph) and entry block (CFG).
- Doubleoctagon: external / OS entry point (call graph only).
- Rounded box: ordinary internal subroutine / basic block.
- Double border: blocks ending in ``rts`` / ``rti`` / ``brk``.

Edge styling:

- Call graph: solid for ``jsr``; dashed orange for ``jmp`` tail-calls.
- CFG: blue for the taken side of a conditional branch; green for the
  fall-through; red for unconditional ``jmp``; dashed grey for the
  rare ``call`` exit kind (currently unused by :mod:`fantasm.api.cfg`
  but reserved).
"""

from __future__ import annotations

import io
import re
import shutil
import subprocess
from collections.abc import Iterable, Sequence
from pathlib import Path

import networkx as nx

from .cfg import BasicBlock, resolve_sub_node


# --- Palette -------------------------------------------------------

_SOLARIZED_BASE03 = "#002b36"
_SOLARIZED_BASE02 = "#073642"
_SOLARIZED_BASE01 = "#586e75"
_SOLARIZED_BASE2 = "#eee8d5"
_SOLARIZED_BASE3 = "#fdf6e3"
_SOLARIZED_YELLOW = "#b58900"
_SOLARIZED_ORANGE = "#cb4b16"
_SOLARIZED_RED = "#dc322f"
_SOLARIZED_BLUE = "#268bd2"
_SOLARIZED_GREEN = "#859900"
_SOLARIZED_VIOLET = "#6c71c4"

_EXIT_KIND_COLOUR = {
    "branch": _SOLARIZED_BLUE,
    "fall": _SOLARIZED_GREEN,
    "jump": _SOLARIZED_RED,
    "call": _SOLARIZED_VIOLET,
    "return": _SOLARIZED_BASE01,
}

_EXIT_KIND_STYLE = {
    "branch": "solid",
    "fall": "solid",
    "jump": "solid",
    "call": "dashed",
    "return": "solid",
}


# --- Filtering -----------------------------------------------------


def _bfs_layer(
    graph: nx.DiGraph,
    sources: Iterable[str],
    depth: int | None,
    direction: str,
) -> set[str]:
    """Breadth-first search from ``sources`` to at most ``depth`` hops.

    ``direction`` is ``"down"`` (follow successors) or ``"up"`` (follow
    predecessors). ``depth=None`` means unlimited.
    """
    visited: dict[str, int] = {source: 0 for source in sources}
    queue: list[str] = list(visited)
    head = 0
    while head < len(queue):
        node = queue[head]
        head += 1
        current_depth = visited[node]
        if depth is not None and current_depth >= depth:
            continue
        neighbours = (
            graph.successors(node)
            if direction == "down"
            else graph.predecessors(node)
        )
        for neighbour in neighbours:
            if neighbour not in visited:
                visited[neighbour] = current_depth + 1
                queue.append(neighbour)
    return set(visited)


def filter_call_graph(
    graph: nx.DiGraph,
    *,
    focus: Sequence[str] | None = None,
    up_depth: int | None = None,
    down_depth: int | None = None,
    exclude_external: bool = False,
    include_pattern: str | None = None,
    exclude_pattern: str | None = None,
    min_degree: int = 0,
) -> nx.DiGraph:
    """Return a filtered copy of a call graph.

    The filters compose. When ``focus`` is supplied, the result is
    restricted to a neighbourhood: ancestors up to ``up_depth`` hops
    and descendants up to ``down_depth`` hops. Either may be ``None``
    (unlimited). When ``focus`` is omitted, the depth options are
    ignored and the whole graph is considered.

    ``include_pattern`` / ``exclude_pattern`` are regex strings matched
    against each node's ``name`` attribute (or its id if no name).
    ``min_degree`` drops low-connectivity nodes; focus nodes are
    immune.
    """
    focus_ids: list[str] = []
    if focus:
        for target in focus:
            node_id = resolve_sub_node(graph, target)
            if node_id is None:
                raise ValueError(
                    f"focus target {target!r} not found in call graph"
                )
            focus_ids.append(node_id)
        reach: set[str] = set(focus_ids)
        if up_depth is None or up_depth > 0:
            reach.update(_bfs_layer(graph, focus_ids, up_depth, "up"))
        if down_depth is None or down_depth > 0:
            reach.update(_bfs_layer(graph, focus_ids, down_depth, "down"))
        selected = reach
    else:
        selected = set(graph.nodes)

    if exclude_external:
        selected = {
            node_id
            for node_id in selected
            if not graph.nodes[node_id].get("external")
        }

    if include_pattern:
        regex = re.compile(include_pattern)
        selected = {
            node_id
            for node_id in selected
            if regex.search(graph.nodes[node_id].get("name", node_id))
        }

    if exclude_pattern:
        regex = re.compile(exclude_pattern)
        selected = {
            node_id
            for node_id in selected
            if not regex.search(graph.nodes[node_id].get("name", node_id))
        }

    selected.update(focus_ids)

    subgraph: nx.DiGraph = graph.subgraph(selected).copy()

    if min_degree > 0:
        protected = set(focus_ids)
        low_degree = {
            node_id
            for node_id in subgraph.nodes
            if node_id not in protected
            and (subgraph.in_degree(node_id) + subgraph.out_degree(node_id))
            < min_degree
        }
        subgraph.remove_nodes_from(low_degree)

    for node_id in focus_ids:
        if subgraph.has_node(node_id):
            subgraph.nodes[node_id]["focused"] = True

    return subgraph


# --- Dot emission --------------------------------------------------


class _Raw:
    """Marker for attribute values already in dot syntax.

    Use for HTML-like labels (``<...>``) and pre-assembled multi-line
    labels with embedded ``\\n`` / ``\\l`` escapes, which would
    otherwise be mangled by :func:`_escape_dot_text`.
    """

    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text


def _escape_dot_text(value: str) -> str:
    """Escape arbitrary user text for inclusion in a dot quoted string.

    Doubles literal backslashes and escapes the surrounding quote
    character. Newline / tab characters are converted into the dot
    escape sequences ``\\n`` / ``\\t`` so the resulting label renders
    on multiple lines rather than embedding a real newline in the dot
    source.
    """
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\t", "\\t")
    )


def _dot_string(value: str) -> str:
    """Quote ``value`` for use as a dot node id or single-piece attribute."""
    return f'"{_escape_dot_text(value)}"'


def _dot_label(*parts: str, separator: str = "\\n") -> _Raw:
    """Build a multi-line dot label from text pieces.

    Each piece is escaped so embedded backslashes / quotes are safe;
    pieces are then joined with ``separator`` (default centered
    newline, ``\\n`` — use ``\\l`` for left-justified). The returned
    :class:`_Raw` carries the fully-quoted label and bypasses further
    escaping in :func:`_format_attrs`.
    """
    escaped = [_escape_dot_text(part) for part in parts]
    return _Raw('"' + separator.join(escaped) + '"')


def _html_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _format_attrs(attrs: dict[str, object]) -> str:
    """Render a ``[key="value", ...]`` attribute list, or ``""`` if empty.

    :class:`_Raw` values are emitted verbatim (already valid dot
    syntax); plain strings are escaped and double-quoted.
    """
    parts = []
    for key, value in attrs.items():
        if isinstance(value, _Raw):
            parts.append(f"{key}={value.text}")
        else:
            parts.append(f"{key}={_dot_string(str(value))}")
    return f" [{', '.join(parts)}]" if parts else ""


def _call_graph_node_attrs(graph: nx.DiGraph, node_id: str) -> dict[str, object]:
    attrs = graph.nodes[node_id]
    name = attrs.get("name") or node_id
    focused = attrs.get("focused", False)
    external = attrs.get("external", False)
    in_degree = graph.in_degree(node_id)

    node_attrs: dict[str, object] = {"label": name}
    if external:
        node_attrs["shape"] = "doubleoctagon"
        node_attrs["style"] = "filled"
        node_attrs["fillcolor"] = _SOLARIZED_BASE2
        node_attrs["color"] = _SOLARIZED_BASE01
    elif in_degree == 0:
        node_attrs["shape"] = "hexagon"
        node_attrs["style"] = "filled,bold"
        node_attrs["fillcolor"] = _SOLARIZED_BLUE
        node_attrs["fontcolor"] = "white"
        node_attrs["color"] = _SOLARIZED_BASE02
    else:
        node_attrs["shape"] = "box"
        node_attrs["style"] = "rounded,filled"
        node_attrs["fillcolor"] = _SOLARIZED_BASE3
        node_attrs["color"] = _SOLARIZED_BASE01

    if focused:
        node_attrs["penwidth"] = "2.5"
        node_attrs["color"] = _SOLARIZED_ORANGE

    return node_attrs


def call_graph_to_dot(
    graph: nx.DiGraph,
    *,
    title: str | None = None,
) -> str:
    """Render a call graph (``DiGraph``) as graphviz dot source."""
    lines: list[str] = []
    name = title or "call_graph"
    lines.append(f"digraph {_dot_string(name)} {{")
    lines.append("  rankdir=LR;")
    lines.append('  graph [bgcolor="white", fontname="Helvetica", fontsize=12];')
    lines.append(
        '  node [fontname="Helvetica", fontsize=10, margin="0.12,0.06"];'
    )
    lines.append(
        f'  edge [fontname="Helvetica", fontsize=9, color="{_SOLARIZED_BASE01}"];'
    )
    if title:
        lines.append(
            f'  labelloc="t"; label={_dot_string(title)};'
        )

    for node_id in sorted(graph.nodes):
        attrs = _call_graph_node_attrs(graph, node_id)
        lines.append(f"  {_dot_string(node_id)}{_format_attrs(attrs)};")

    for source, target, edata in sorted(graph.edges(data=True)):
        edge_type = edata.get("type", "jsr")
        sites = edata.get("call_sites", [])
        edge_attrs: dict[str, str] = {}
        if edge_type == "jmp":
            edge_attrs["color"] = _SOLARIZED_ORANGE
            edge_attrs["style"] = "dashed"
            edge_attrs["label"] = "jmp"
        if len(sites) > 1:
            edge_attrs.setdefault("label", f"{len(sites)}×")
            edge_attrs["penwidth"] = "1.5"
        lines.append(
            f"  {_dot_string(source)} -> {_dot_string(target)}"
            f"{_format_attrs(edge_attrs)};"
        )

    lines.append("}")
    return "\n".join(lines) + "\n"


def _block_node_id(block_addr: int) -> str:
    return f"blk_{block_addr:04X}"


def _format_block_label(block: BasicBlock) -> str:
    """Render an HTML-like dot label for a basic block.

    Header row shows the block's start address (and any labels carried
    by the first instruction); subsequent rows list each instruction
    with mnemonic, operand, and any inline comment.
    """
    header_cells: list[str] = []
    first_item = block.items[0]
    labels = first_item.get("labels") or []
    if labels:
        header_cells.append(
            f'<B>{_html_escape(", ".join(labels))}</B>'
        )
    header_cells.append(f'<FONT POINT-SIZE="9">&amp;{block.addr:04X}</FONT>')
    header = "<BR/>".join(header_cells)

    rows = [
        '<TR><TD ALIGN="LEFT" BALIGN="LEFT" BGCOLOR="'
        + _SOLARIZED_BASE2
        + '">'
        + header
        + "</TD></TR>"
    ]
    for item in block.items:
        mnemonic = item.get("mnemonic", "")
        operand = item.get("operand", "")
        comment = item.get("comment_inline") or ""
        instruction = mnemonic.lower()
        if operand:
            instruction = f"{instruction} {operand}"
        cell = _html_escape(instruction)
        if comment:
            cell += (
                '  <FONT COLOR="'
                + _SOLARIZED_BASE01
                + '"><I>; '
                + _html_escape(comment)
                + "</I></FONT>"
            )
        rows.append(f'<TR><TD ALIGN="LEFT">{cell}</TD></TR>')

    return (
        '<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" '
        'CELLPADDING="2">'
        + "".join(rows)
        + "</TABLE>>"
    )


def basic_blocks_to_graph(
    blocks: Sequence[BasicBlock],
    *,
    sub_name: str | None = None,
    sub_addr: int | None = None,
) -> nx.DiGraph:
    """Build a ``DiGraph`` from a list of basic blocks.

    Nodes are keyed by ``blk_NNNN`` (4-digit uppercase hex) and carry
    ``addr``, ``label`` (HTML), ``is_entry``, ``is_return``. Edges
    carry ``kind`` (one of the :class:`BasicBlockExit` kinds) and
    ``target_addr``. External targets (branch / jump destinations
    outside the supplied blocks) are emitted as placeholder nodes with
    ``external=True``.
    """
    graph: nx.DiGraph = nx.DiGraph()
    if sub_name is not None:
        graph.graph["sub_name"] = sub_name
    if sub_addr is not None:
        graph.graph["sub_addr"] = sub_addr

    block_addrs = {block.addr for block in blocks}
    entry_addr = blocks[0].addr if blocks else None

    for block in blocks:
        is_return = any(exit_record.kind == "return" for exit_record in block.exits)
        node_id = _block_node_id(block.addr)
        graph.add_node(
            node_id,
            addr=block.addr,
            label=_format_block_label(block),
            is_entry=(block.addr == entry_addr),
            is_return=is_return,
            external=False,
        )

    for block in blocks:
        source_id = _block_node_id(block.addr)
        for exit_record in block.exits:
            if exit_record.kind == "return":
                continue
            target = exit_record.target
            if target is None:
                continue
            if target in block_addrs:
                target_id = _block_node_id(target)
            else:
                target_id = f"ext_{target:04X}"
                if not graph.has_node(target_id):
                    graph.add_node(
                        target_id,
                        addr=target,
                        label=f"&{target:04X}",
                        is_entry=False,
                        is_return=False,
                        external=True,
                    )
            graph.add_edge(
                source_id,
                target_id,
                kind=exit_record.kind,
                target_addr=target,
            )

    return graph


def _basic_block_node_attrs(graph: nx.DiGraph, node_id: str) -> dict[str, object]:
    attrs = graph.nodes[node_id]
    if attrs.get("external"):
        # External-target placeholder: plain-text label, auto-escaped.
        return {
            "label": attrs.get("label", node_id),
            "shape": "cds",
            "style": "filled,dashed",
            "fillcolor": _SOLARIZED_BASE2,
            "color": _SOLARIZED_BASE01,
            "fontname": "Menlo",
            "fontsize": "9",
        }

    # Internal block: HTML-like label produced by _format_block_label,
    # passed through verbatim via _Raw.
    label = attrs.get("label", node_id)
    node_attrs: dict[str, object] = {
        "label": _Raw(label) if label.startswith("<") else label,
        "shape": "box",
        "style": "rounded,filled",
        "fillcolor": _SOLARIZED_BASE3,
        "color": _SOLARIZED_BASE01,
        "fontname": "Menlo",
        "fontsize": "9",
    }
    if attrs.get("is_entry"):
        node_attrs["color"] = _SOLARIZED_BLUE
        node_attrs["penwidth"] = "2.0"
    if attrs.get("is_return"):
        node_attrs["style"] = "rounded,filled,bold"
        node_attrs["color"] = _SOLARIZED_RED
        node_attrs["penwidth"] = "2.0"
    return node_attrs


def basic_blocks_to_dot(
    blocks: Sequence[BasicBlock],
    *,
    sub_name: str | None = None,
    sub_addr: int | None = None,
) -> str:
    """Render a per-subroutine basic-block CFG as graphviz dot source."""
    graph = basic_blocks_to_graph(
        blocks, sub_name=sub_name, sub_addr=sub_addr
    )

    if sub_addr is not None and sub_name:
        title = f"{sub_name} (&{sub_addr:04X})"
    elif sub_name:
        title = sub_name
    elif sub_addr is not None:
        title = f"&{sub_addr:04X}"
    else:
        title = "cfg"

    lines: list[str] = []
    lines.append(f"digraph {_dot_string('cfg_' + title)} {{")
    lines.append("  rankdir=TB;")
    lines.append('  graph [bgcolor="white", fontname="Helvetica", fontsize=12];')
    lines.append(
        '  node [fontname="Menlo", fontsize=9, margin="0.10,0.05"];'
    )
    lines.append(
        f'  edge [fontname="Helvetica", fontsize=9, color="{_SOLARIZED_BASE01}"];'
    )
    lines.append(f'  labelloc="t"; label={_dot_string(title)};')

    for node_id in sorted(graph.nodes, key=lambda n: graph.nodes[n].get("addr", 0)):
        attrs = _basic_block_node_attrs(graph, node_id)
        lines.append(f"  {_dot_string(node_id)}{_format_attrs(attrs)};")

    for source, target, edata in sorted(graph.edges(data=True)):
        kind = edata.get("kind", "fall")
        edge_attrs: dict[str, str] = {
            "color": _EXIT_KIND_COLOUR.get(kind, _SOLARIZED_BASE01),
            "style": _EXIT_KIND_STYLE.get(kind, "solid"),
            "label": kind,
        }
        lines.append(
            f"  {_dot_string(source)} -> {_dot_string(target)}"
            f"{_format_attrs(edge_attrs)};"
        )

    lines.append("}")
    return "\n".join(lines) + "\n"


# --- GraphML emission ---------------------------------------------


def _graphml_safe_graph(graph: nx.DiGraph) -> nx.DiGraph:
    """Return a copy with HTML labels stripped to plain-text alternatives.

    GraphML doesn't preserve the dot HTML-label syntax, so we substitute
    a plain-text ``label`` derived from each node's textual content
    (block addr for CFG nodes, ``name + addr`` for call-graph nodes).
    """
    out: nx.DiGraph = nx.DiGraph()
    out.graph.update({k: v for k, v in graph.graph.items() if isinstance(v, (str, int, float, bool))})
    for node_id, attrs in graph.nodes(data=True):
        cleaned: dict[str, object] = {}
        for key, value in attrs.items():
            if key == "label" and isinstance(value, str) and value.startswith("<"):
                # CFG block: synthesise a plain label.
                addr = attrs.get("addr")
                cleaned["label"] = (
                    f"&{addr:04X}" if isinstance(addr, int) else node_id
                )
                continue
            if isinstance(value, (str, int, float, bool)):
                cleaned[key] = value
            elif value is None:
                continue
            else:
                cleaned[key] = str(value)
        out.add_node(node_id, **cleaned)
    for source, target, attrs in graph.edges(data=True):
        cleaned_edge: dict[str, object] = {}
        for key, value in attrs.items():
            if isinstance(value, (str, int, float, bool)):
                cleaned_edge[key] = value
            elif isinstance(value, (list, tuple)):
                cleaned_edge[key] = ", ".join(str(item) for item in value)
            elif value is None:
                continue
            else:
                cleaned_edge[key] = str(value)
        out.add_edge(source, target, **cleaned_edge)
    return out


def call_graph_to_graphml(graph: nx.DiGraph) -> str:
    """Render a call graph as GraphML text."""
    safe = _graphml_safe_graph(graph)
    buffer = io.BytesIO()
    nx.write_graphml(safe, buffer, encoding="utf-8")
    return buffer.getvalue().decode("utf-8")


def basic_blocks_to_graphml(
    blocks: Sequence[BasicBlock],
    *,
    sub_name: str | None = None,
    sub_addr: int | None = None,
) -> str:
    """Render a per-subroutine basic-block CFG as GraphML text."""
    graph = basic_blocks_to_graph(
        blocks, sub_name=sub_name, sub_addr=sub_addr
    )
    return call_graph_to_graphml(graph)


# --- dot binary helper --------------------------------------------


class DotBinaryNotFoundError(FileNotFoundError):
    """The graphviz ``dot`` (or other engine) binary is not on PATH."""


def render_dot(
    dot_text: str,
    output_filepath: str | Path,
    *,
    format: str = "png",
    engine: str = "dot",
) -> Path:
    """Pipe ``dot_text`` into ``engine`` and write the rendered output.

    Returns the output path. Raises :class:`DotBinaryNotFoundError` if
    the engine binary is missing, and propagates
    :class:`subprocess.CalledProcessError` from the engine itself.
    """
    binary_filepath = shutil.which(engine)
    if binary_filepath is None:
        raise DotBinaryNotFoundError(
            f"{engine!r} not on PATH; install graphviz to render dot output"
        )
    output_filepath = Path(output_filepath)
    subprocess.run(
        [binary_filepath, f"-T{format}", "-o", str(output_filepath)],
        input=dot_text.encode("utf-8"),
        check=True,
    )
    return output_filepath


__all__ = [
    "DotBinaryNotFoundError",
    "basic_blocks_to_dot",
    "basic_blocks_to_graph",
    "basic_blocks_to_graphml",
    "call_graph_to_dot",
    "call_graph_to_graphml",
    "filter_call_graph",
    "render_dot",
]
