"""``fantasm cfg`` — inter-procedural call-graph queries."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from ..api.audit import find_sub
from ..api.cfg import find_basic_blocks, resolve_sub_node
from ..api.context import compute_call_depths, extract_sub_context
from ..api.dot import (
    DotBinaryNotFoundError,
    basic_blocks_to_dot,
    basic_blocks_to_graphml,
    call_graph_to_dot,
    call_graph_to_graphml,
    filter_call_graph,
    render_dot,
)
from ..cli_helpers import analysis_context


@click.group(help="Inter-procedural call-graph queries.")
def cfg() -> None:
    pass


@cfg.command("leaves", help="List leaf subroutines (no internal callees).")
@click.argument("version_id")
@report_output(reports={"leaves": "Leaf subroutines"})
def cfg_leaves(version_id: str) -> Reports:
    actx = analysis_context(click.get_current_context(), version_id)
    graph = actx.call_graph

    table = (
        TableContent(
            title=f"Leaf subroutines in {version_id}",
            description="Subroutines whose only callees are external OS entries.",
        )
        .add_column("addr", "Addr")
        .add_column("name", "Name")
        .add_column("in_degree", "Callers")
        .add_column("external", "External")
    )
    for node_id in sorted(graph.nodes):
        if graph.out_degree(node_id) != 0:
            continue
        attrs = graph.nodes[node_id]
        table.add_row(
            addr=node_id,
            name=attrs.get("name", node_id),
            in_degree=str(graph.in_degree(node_id)),
            external="yes" if attrs.get("external") else "",
        )
    return Reports(leaves=Report(data=table))


@cfg.command("roots", help="List root subroutines (in-degree 0, internal).")
@click.argument("version_id")
@report_output(reports={"roots": "Root subroutines"})
def cfg_roots(version_id: str) -> Reports:
    actx = analysis_context(click.get_current_context(), version_id)
    graph = actx.call_graph

    table = (
        TableContent(
            title=f"Root subroutines in {version_id}",
            description="Internal subroutines with no callers.",
        )
        .add_column("addr", "Addr")
        .add_column("name", "Name")
        .add_column("out_degree", "Callees")
    )
    for node_id in sorted(graph.nodes):
        attrs = graph.nodes[node_id]
        if graph.in_degree(node_id) != 0 or attrs.get("external"):
            continue
        table.add_row(
            addr=node_id,
            name=attrs.get("name", node_id),
            out_degree=str(graph.out_degree(node_id)),
        )
    return Reports(roots=Report(data=table))


@cfg.command("depth", help="List subroutines by call-graph depth (leaves first).")
@click.argument("version_id")
@report_output(reports={"depth": "Subroutine depth"})
def cfg_depth(version_id: str) -> Reports:
    actx = analysis_context(click.get_current_context(), version_id)
    depths = compute_call_depths(actx.call_graph)
    graph = actx.call_graph

    sorted_nodes = sorted(depths.items(), key=lambda x: (-x[1], x[0]))
    table = (
        TableContent(
            title=f"Call-graph depth for {version_id}",
            description=f"{len(depths)} internal subroutines",
        )
        .add_column("depth", "Depth")
        .add_column("addr", "Addr")
        .add_column("name", "Name")
        .add_column("out_degree", "Out")
        .add_column("in_degree", "In")
    )
    for node_id, depth in sorted_nodes:
        attrs = graph.nodes[node_id]
        table.add_row(
            depth=str(depth),
            addr=node_id,
            name=attrs.get("name", node_id),
            out_degree=str(graph.out_degree(node_id)),
            in_degree=str(graph.in_degree(node_id)),
        )
    return Reports(depth=Report(data=table))


@cfg.command("sub", help="Show callers and callees of one subroutine.")
@click.argument("version_id")
@click.argument("target")
@report_output(reports={
    "callers": "Callers of the subroutine",
    "callees": "Callees of the subroutine",
})
def cfg_sub(version_id: str, target: str) -> Reports:
    actx = analysis_context(click.get_current_context(), version_id)
    graph = actx.call_graph
    node_id = resolve_sub_node(graph, target)
    if node_id is None:
        raise click.UsageError(
            f"subroutine {target!r} not found in {version_id}"
        )

    def _ref_table(title: str, neighbours, edge_dir: str):
        tbl = (
            TableContent(title=title)
            .add_column("addr", "Addr")
            .add_column("name", "Name")
            .add_column("type", "Edge")
            .add_column("sites", "Call sites")
        )
        for nb in sorted(neighbours):
            edge = (
                graph.edges[nb, node_id] if edge_dir == "in"
                else graph.edges[node_id, nb]
            )
            tbl.add_row(
                addr=nb,
                name=graph.nodes[nb].get("name", nb),
                type=edge.get("type", "jsr"),
                sites=", ".join(edge.get("call_sites", [])),
            )
        return tbl

    return Reports(
        callers=Report(
            data=_ref_table(
                f"Callers of {graph.nodes[node_id].get('name', node_id)}",
                graph.predecessors(node_id),
                "in",
            )
        ),
        callees=Report(
            data=_ref_table(
                f"Callees of {graph.nodes[node_id].get('name', node_id)}",
                graph.successors(node_id),
                "out",
            )
        ),
    )


@cfg.command(
    "blocks",
    help=(
        "Identify basic blocks within a version's disassembly. "
        "Without --sub, surveys every subroutine. With --sub, shows "
        "only the named subroutine's blocks. --uncommented-only "
        "filters to blocks with zero inline comments and at least "
        "two items, the typical annotation-gap-finding workflow."
    ),
)
@click.argument("version_id")
@click.option(
    "--sub",
    "sub_target",
    help="Restrict to one subroutine (hex address or name).",
)
@click.option(
    "--uncommented-only",
    is_flag=True,
    help="Only show blocks with zero comments and >= 2 items.",
)
@click.option(
    "--min-items",
    type=click.IntRange(1, 100),
    default=2,
    show_default=True,
    help="Minimum item count for a block to be included.",
)
@report_output(reports={"blocks": "Basic blocks"})
def cfg_blocks(
    version_id: str,
    sub_target: str | None,
    uncommented_only: bool,
    min_items: int,
) -> Reports:
    actx = analysis_context(click.get_current_context(), version_id)

    if sub_target is None:
        items = actx.data["items"]
        sub_label = "(all subroutines)"
    else:
        sub = find_sub(actx.audit_subs, sub_target)
        if sub is None:
            raise click.UsageError(
                f"subroutine {sub_target!r} not found in {version_id}"
            )
        items = sub["items"]
        sub_label = f"{sub['name']} (&{sub['addr']:04X})"

    blocks = find_basic_blocks(items)
    if uncommented_only:
        blocks = [
            b for b in blocks if b.commented == 0 and b.total >= 2
        ]
    blocks = [b for b in blocks if b.total >= min_items]

    table = (
        TableContent(
            title=f"Basic blocks in {version_id} / {sub_label}",
            description=(
                f"{len(blocks)} blocks"
                + (" (uncommented only)" if uncommented_only else "")
            ),
        )
        .add_column("addr", "Addr")
        .add_column("items", "Items")
        .add_column("commented", "Commented")
        .add_column("density", "Density")
        .add_column("entries", "Entries")
        .add_column("exits", "Exits")
        .add_column("exit_kinds", "Exit kinds")
    )
    for block in blocks:
        density_pct = (
            100 * block.commented / block.total if block.total else 0.0
        )
        exit_kinds = ", ".join(
            sorted({exit_record.kind for exit_record in block.exits})
        )
        table.add_row(
            addr=f"&{block.addr:04X}",
            items=str(block.total),
            commented=str(block.commented),
            density=f"{density_pct:.0f}%",
            entries=str(len(block.entries)),
            exits=str(len(block.exits)),
            exit_kinds=exit_kinds,
        )
    return Reports(blocks=Report(data=table))


@cfg.command(
    "sub-context",
    help=(
        "Show calling-convention context for one subroutine: body "
        "lines, every call site with surrounding context, and every "
        "exit point. Complements `cfg sub`, which shows the call "
        "graph view."
    ),
)
@click.argument("version_id")
@click.argument("target")
@click.option(
    "--body-window",
    type=click.IntRange(1, 500),
    default=20,
    show_default=True,
    help="Lines of body to show.",
)
@click.option(
    "--caller-context",
    type=click.IntRange(0, 50),
    default=3,
    show_default=True,
    help="Lines before each call site.",
)
@click.option(
    "--after-context",
    type=click.IntRange(0, 50),
    default=2,
    show_default=True,
    help="Lines after each call site.",
)
@click.option(
    "--exit-context",
    type=click.IntRange(0, 50),
    default=3,
    show_default=True,
    help="Lines before each exit instruction.",
)
@report_output(reports={
    "info": "Subroutine summary",
    "body": "Body lines",
    "call_sites": "Call sites with surrounding context",
    "exits": "Exit instructions with surrounding context",
})
def cfg_sub_context(
    version_id: str,
    target: str,
    body_window: int,
    caller_context: int,
    after_context: int,
    exit_context: int,
) -> Reports:
    actx = analysis_context(click.get_current_context(), version_id)
    sub = find_sub(actx.audit_subs, target)
    if sub is None:
        raise click.UsageError(
            f"subroutine {target!r} not found in {version_id}"
        )

    sub_context = extract_sub_context(
        sub, actx.asm_lines, actx.call_graph,
        body_window=body_window,
        caller_context=caller_context,
        after_context=after_context,
        exit_context=exit_context,
    )

    info = (
        TableContent(
            title=f"{sub_context.name} (&{sub_context.addr:04X})",
            description=sub_context.title or "(no title)",
        )
        .add_column("key", "Key")
        .add_column("value", "Value")
        .add_row(key="address", value=f"&{sub_context.addr:04X}")
        .add_row(key="name", value=sub_context.name)
        .add_row(key="title", value=sub_context.title or "")
        .add_row(key="call_sites", value=str(len(sub_context.call_sites)))
        .add_row(key="exit_points", value=str(len(sub_context.exit_points)))
        .add_row(key="body_lines", value=str(len(sub_context.body_lines)))
    )

    body_table = (
        TableContent(title=f"{sub_context.name} body")
        .add_column("line", "Line")
        .add_column("text", "Source")
    )
    for offset, text in enumerate(sub_context.body_lines):
        body_table.add_row(
            line=str(sub_context.body_start_line + offset + 1),
            text=text.rstrip("\n"),
        )

    call_table = (
        TableContent(
            title=f"{sub_context.name} call sites",
            description=f"{len(sub_context.call_sites)} site(s)",
        )
        .add_column("site", "Site")
        .add_column("from", "From sub")
        .add_column("addr", "Addr")
        .add_column("op", "Op")
        .add_column("text", "Source")
    )
    for site_index, site in enumerate(sub_context.call_sites, start=1):
        for line_offset, text in enumerate(site.asm_lines):
            marker = ">>>" if line_offset == site.call_line_index else ""
            call_table.add_row(
                site=f"{site_index}/{len(sub_context.call_sites)}",
                **{"from": site.in_sub_name or "?"},
                addr=f"&{site.addr:04X}",
                op=site.mnemonic.upper(),
                text=f"{marker} {text.rstrip()}".strip(),
            )

    exit_table = (
        TableContent(
            title=f"{sub_context.name} exits",
            description=f"{len(sub_context.exit_points)} exit(s)",
        )
        .add_column("exit", "Exit")
        .add_column("addr", "Addr")
        .add_column("op", "Op")
        .add_column("text", "Source")
    )
    for exit_index, exit_point in enumerate(sub_context.exit_points, start=1):
        for line_offset, text in enumerate(exit_point.asm_lines):
            marker = ">>>" if line_offset == exit_point.exit_line_index else ""
            exit_table.add_row(
                exit=f"{exit_index}/{len(sub_context.exit_points)}",
                addr=f"&{exit_point.addr:04X}",
                op=exit_point.mnemonic.upper(),
                text=f"{marker} {text.rstrip()}".strip(),
            )

    return Reports(
        info=Report(data=info),
        body=Report(data=body_table),
        call_sites=Report(data=call_table),
        exits=Report(data=exit_table),
    )


def _write_graph_output(
    text: str,
    output_filepath: Path | None,
    *,
    render_format: str | None,
) -> None:
    """Emit graph source to stdout / a file, optionally piping through ``dot``."""
    if render_format is not None:
        if output_filepath is None:
            raise click.UsageError(
                "--render requires --output (the rendered image path)"
            )
        try:
            render_dot(text, output_filepath, format=render_format)
        except DotBinaryNotFoundError as exc:
            raise click.UsageError(str(exc)) from exc
        click.echo(f"wrote {output_filepath}", err=True)
        return
    if output_filepath is None:
        sys.stdout.write(text)
    else:
        output_filepath.write_text(text)
        click.echo(f"wrote {output_filepath}", err=True)


@cfg.command(
    "dot-call-graph",
    help=(
        "Emit the inter-procedural call graph as graphviz dot (or "
        "GraphML). Pipe into ``dot -Tpng`` / ``dot -Tsvg`` for an "
        "image, or use --render to do that in one step. Filters let "
        "you focus on a neighbourhood; the whole graph for a real ROM "
        "is usually too dense to read."
    ),
)
@click.argument("version_id")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["dot", "graphml"]),
    default="dot",
    show_default=True,
    help="Graph source format.",
)
@click.option(
    "-o",
    "--output",
    "output_filepath",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write source / rendered image to this file (default: stdout for source).",
)
@click.option(
    "--render",
    "render_format",
    type=click.Choice(["png", "svg", "pdf"]),
    default=None,
    help="Shell out to ``dot`` and write a rendered image instead of source.",
)
@click.option(
    "-F",
    "--focus",
    "focus",
    multiple=True,
    help="Centre on this subroutine (hex addr or name). Repeatable.",
)
@click.option(
    "--depth",
    type=click.IntRange(0, 1000),
    default=None,
    help="Neighbourhood radius (both ancestors and descendants).",
)
@click.option(
    "--up-depth",
    type=click.IntRange(0, 1000),
    default=None,
    help="Ancestor radius (callers of --focus). Overrides --depth.",
)
@click.option(
    "--down-depth",
    type=click.IntRange(0, 1000),
    default=None,
    help="Descendant radius (callees of --focus). Overrides --depth.",
)
@click.option(
    "--exclude-external",
    is_flag=True,
    help="Drop OS / external-entry nodes (those above the ROM range).",
)
@click.option(
    "--include-pattern",
    default=None,
    help="Keep nodes whose name matches this regex.",
)
@click.option(
    "--exclude-pattern",
    default=None,
    help="Drop nodes whose name matches this regex.",
)
@click.option(
    "--min-degree",
    type=click.IntRange(0, 100),
    default=0,
    show_default=True,
    help="Drop nodes whose total degree is below this threshold (focus exempt).",
)
def cfg_dot_call_graph(
    version_id: str,
    output_format: str,
    output_filepath: Path | None,
    render_format: str | None,
    focus: tuple[str, ...],
    depth: int | None,
    up_depth: int | None,
    down_depth: int | None,
    exclude_external: bool,
    include_pattern: str | None,
    exclude_pattern: str | None,
    min_degree: int,
) -> None:
    actx = analysis_context(click.get_current_context(), version_id)
    graph = actx.call_graph

    if focus:
        effective_up = up_depth if up_depth is not None else depth
        effective_down = down_depth if down_depth is not None else depth
    else:
        effective_up = None
        effective_down = None

    try:
        filtered = filter_call_graph(
            graph,
            focus=focus or None,
            up_depth=effective_up,
            down_depth=effective_down,
            exclude_external=exclude_external,
            include_pattern=include_pattern,
            exclude_pattern=exclude_pattern,
            min_degree=min_degree,
        )
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc

    if output_format == "graphml":
        text = call_graph_to_graphml(filtered)
    else:
        title = f"{version_id} call graph"
        text = call_graph_to_dot(filtered, title=title)

    _write_graph_output(text, output_filepath, render_format=render_format)


@cfg.command(
    "dot-flow",
    help=(
        "Emit the basic-block control-flow graph for ONE subroutine "
        "as graphviz dot (or GraphML). Each block becomes a node "
        "listing its instructions; edges are coloured by exit kind "
        "(branch / fall / jump). Use --render to produce a png/svg/pdf "
        "in one step."
    ),
)
@click.argument("version_id")
@click.argument("target")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["dot", "graphml"]),
    default="dot",
    show_default=True,
    help="Graph source format.",
)
@click.option(
    "-o",
    "--output",
    "output_filepath",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write source / rendered image to this file (default: stdout for source).",
)
@click.option(
    "--render",
    "render_format",
    type=click.Choice(["png", "svg", "pdf"]),
    default=None,
    help="Shell out to ``dot`` and write a rendered image instead of source.",
)
def cfg_dot_flow(
    version_id: str,
    target: str,
    output_format: str,
    output_filepath: Path | None,
    render_format: str | None,
) -> None:
    actx = analysis_context(click.get_current_context(), version_id)
    sub = find_sub(actx.audit_subs, target)
    if sub is None:
        raise click.UsageError(
            f"subroutine {target!r} not found in {version_id}"
        )
    blocks = find_basic_blocks(sub["items"])
    if not blocks:
        raise click.UsageError(
            f"no basic blocks recovered for {sub['name']} "
            f"(&{sub['addr']:04X}) — empty or non-code body?"
        )

    if output_format == "graphml":
        text = basic_blocks_to_graphml(
            blocks, sub_name=sub["name"], sub_addr=sub["addr"]
        )
    else:
        text = basic_blocks_to_dot(
            blocks, sub_name=sub["name"], sub_addr=sub["addr"]
        )

    _write_graph_output(text, output_filepath, render_format=render_format)
