"""Click-based command-line entrypoint for fantasm."""

from __future__ import annotations

from pathlib import Path

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from . import __version__
from .api.asm_extract import extract_section
from .api.backfill import compose_chained_map, propose_propagations
from .api.audit import (
    ALL_FLAGS,
    end_type,
    find_sub,
    find_undeclared_subs,
    load_subroutines,
)
from .api.audit import build_memory_regions
from .api.cfg import build_call_graph, resolve_sub_node
from .api.comment_check import run_checks
from .api.compare import compare_roms
from .api.context import compute_call_depths
from .api.find_shared import (
    find_matching_spans,
    load_rom,
    matching_byte_count,
    parse_rom_spec,
)
from .api.fingerprint import (
    find_duplicate_blocks,
    fingerprint_blocks,
)
from .api.insert_point import AlreadyDeclared, compute_insert_point
from .api.labels import (
    build_target_refs,
    classify_labels,
    collect_auto_labels,
    sort_labels,
)
from .api.lint import (
    address_in_ranges,
    address_ranges_from_data,
    extract_annotations,
)
from .api.promote import analyze_labels
from .api.paths import project_rom_prefixes, project_versions_dirpath
from .api.project import (
    ProjectInitConfig,
    add_version,
    init_project,
    list_versions,
)
from .api.verify import (
    BeebasmNotFoundError,
    verify_round_trip,
)
from .api.version_graph import (
    NoPathError,
    VersionGraphError,
    VersionNotInGraphError,
    load_version_graph,
)
from .cli_helpers import (
    effective_regions_for,
    require_project,
    resolve_version_files,
)
from .config import ProjectContext, resolve_project_context


@click.group(
    help="Fantasm — the Fantastic (dis-/re-)Assembly tools for 6502 code.",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(__version__, prog_name="fantasm")
@click.option(
    "--project-root",
    "project_root_dirpath",
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    envvar="FANTASM_PROJECT_ROOT",
    help=(
        "Project root directory. Overrides FANTASM_PROJECT_ROOT. "
        "If neither is given, fantasm searches upwards from the current "
        "directory for a fantasm.toml."
    ),
)
@click.pass_context
def main(ctx: click.Context, project_root_dirpath: Path | None) -> None:
    ctx.ensure_object(dict)
    ctx.obj["project"] = resolve_project_context(project_root_dirpath)


@main.command(help="Show the resolved project context.")
@report_output(reports={"project": "Resolved project context"})
def info() -> Reports:
    project: ProjectContext = click.get_current_context().obj["project"]
    table = (
        TableContent(
            title="Fantasm project",
            description="Resolved project context for the current invocation.",
        )
        .add_column("key", "Key")
        .add_column("value", "Value")
        .add_row(
            key="project_root",
            value=str(project.root_dirpath) if project.root_dirpath else "(unresolved)",
        )
        .add_row(
            key="config_filepath",
            value=str(project.config_filepath) if project.config_filepath else "(none)",
        )
        .add_row(
            key="config_keys",
            value=", ".join(sorted(project.config)) if project.config else "(empty)",
        )
    )
    return Reports(project=Report(data=table))


@main.command(
    help=(
        "Verify a disassembly round-trips: assemble its .asm with "
        "beebasm and compare bytes to the original ROM."
    ),
)
@click.argument("version_id")
@click.pass_context
def verify(ctx: click.Context, version_id: str) -> None:
    project_context = require_project(ctx)
    files = resolve_version_files(project_context, version_id)
    try:
        result = verify_round_trip(files.rom_filepath, files.asm_filepath)
    except FileNotFoundError as exc:
        raise click.UsageError(str(exc)) from exc
    except BeebasmNotFoundError as exc:
        raise click.UsageError(str(exc)) from exc

    if result.matched:
        click.echo(
            f"Verification PASSED: {result.rom_size} bytes match"
        )
        return
    click.echo(
        f"Verification FAILED: rom={result.rom_size}b "
        f"assembled={result.assembled_size}b "
        + (
            f"first_diff=&{result.first_diff_offset:04X}"
            if result.first_diff_offset is not None
            else "(beebasm error)"
        ),
        err=True,
    )
    if result.beebasm_returncode != 0 and result.beebasm_stderr:
        click.echo(result.beebasm_stderr, err=True)
    ctx.exit(1)


@main.command(
    help=(
        "Compare two ROM versions at byte / opcode / full-instruction "
        "granularity and print a diff report."
    ),
)
@click.argument("version_a")
@click.argument("version_b")
@click.option(
    "--cpu",
    default="6502",
    show_default=True,
    help='Default CPU: "6502" or "65c02".',
)
@click.option(
    "--rom-base",
    type=click.IntRange(0, 0xFFFF),
    default=0x8000,
    show_default=True,
    help="ROM load address used for diff-line address formatting.",
)
@click.pass_context
def compare(
    ctx: click.Context, version_a: str, version_b: str, cpu: str, rom_base: int
) -> None:
    project_context = require_project(ctx)
    files_a = resolve_version_files(project_context, version_a)
    files_b = resolve_version_files(project_context, version_b)

    if not files_a.rom_filepath.exists():
        raise click.UsageError(
            f"ROM file not found: {files_a.rom_filepath}"
        )
    if not files_b.rom_filepath.exists():
        raise click.UsageError(
            f"ROM file not found: {files_b.rom_filepath}"
        )

    data_a = files_a.rom_filepath.read_bytes()
    data_b = files_b.rom_filepath.read_bytes()
    report = compare_roms(
        data_a, data_b, version_a, version_b,
        cpu_a=cpu, cpu_b=cpu, rom_base=rom_base,
    )
    click.echo(report)


@main.group(help="Subroutine annotation audit.")
def audit() -> None:
    pass


@audit.command(
    "summary",
    help="List every subroutine with its computed flags.",
)
@click.argument("version_id")
@click.option(
    "--flag",
    type=click.Choice(ALL_FLAGS, case_sensitive=False),
    help="Restrict to subroutines carrying this flag.",
)
@report_output(reports={"summary": "Subroutine summary"})
def audit_summary(version_id: str, flag: str | None) -> Reports:
    import json as _json

    from .api.audit import build_memory_regions

    ctx = click.get_current_context()
    project_context = require_project(ctx)
    files = resolve_version_files(project_context, version_id)
    if not files.json_filepath.exists():
        raise click.UsageError(
            f"JSON not found: {files.json_filepath} (run disassemble first)"
        )

    base_regions = effective_regions_for(project_context, version_id)
    data = _json.loads(files.json_filepath.read_text())
    memory_regions = build_memory_regions(
        data["meta"], base_regions=base_regions
    )
    subs = load_subroutines(
        files.json_filepath, memory_regions=memory_regions
    )
    if flag:
        flag_upper = flag.upper()
        subs = [s for s in subs if flag_upper in s["flags"]]

    table = (
        TableContent(
            title=f"Subroutines in {version_id}",
            description=(
                f"{len(subs)} subroutines"
                + (f" with flag {flag.upper()}" if flag else "")
            ),
        )
        .add_column("addr", "Addr")
        .add_column("name", "Name")
        .add_column("end", "End")
        .add_column("items", "Code/Data")
        .add_column("flags", "Flags")
    )
    for sub in subs:
        table.add_row(
            addr=f"&{sub['addr']:04X}",
            name=sub["name"],
            end=end_type(sub),
            items=f"{sub['code_count']}/{sub['data_count']}",
            flags=",".join(sorted(sub["flags"])) if sub["flags"] else "",
        )
    return Reports(summary=Report(data=table))


@audit.command(
    "undeclared",
    help="List JSR targets that lack subroutine() declarations.",
)
@click.argument("version_id")
@report_output(reports={"undeclared": "Undeclared JSR targets"})
def audit_undeclared(version_id: str) -> Reports:
    ctx = click.get_current_context()
    project_context = require_project(ctx)
    files = resolve_version_files(project_context, version_id)
    if not files.json_filepath.exists():
        raise click.UsageError(
            f"JSON not found: {files.json_filepath} (run disassemble first)"
        )

    candidates = find_undeclared_subs(files.json_filepath)
    table = (
        TableContent(
            title=f"Undeclared JSR targets in {version_id}",
            description=f"{len(candidates)} candidates",
        )
        .add_column("addr", "Addr")
        .add_column("name", "Name")
        .add_column("range", "Range")
        .add_column("items", "Code/Data")
        .add_column("calls", "Calls")
        .add_column("container", "Container")
    )
    for c in candidates:
        table.add_row(
            addr=f"&{c['addr']:04X}",
            name=c["name"],
            range=c["range_str"],
            items=f"{c['code_count']}/{c['data_count']}",
            calls=str(c["caller_count"]),
            container=c["container"],
        )
    return Reports(undeclared=Report(data=table))


@main.group(help="Comment / annotation consistency checks.")
def comments() -> None:
    pass


@comments.command(
    "check",
    help=(
        "Run the comment-vs-code consistency checks against the "
        "version's JSON output."
    ),
)
@click.argument("version_id")
@click.option(
    "--sub",
    "sub_target",
    help="Restrict to the subroutine starting at this hex address.",
)
@report_output(reports={"findings": "Comment-check findings"})
def comments_check(version_id: str, sub_target: str | None) -> Reports:
    import json as _json

    ctx = click.get_current_context()
    project_context = require_project(ctx)
    files = resolve_version_files(project_context, version_id)
    if not files.json_filepath.exists():
        raise click.UsageError(
            f"JSON not found: {files.json_filepath} (run disassemble first)"
        )

    data = _json.loads(files.json_filepath.read_text())
    base_regions = effective_regions_for(project_context, version_id)
    try:
        findings = run_checks(data, sub_target=sub_target, regions=base_regions)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc

    high = sum(1 for f in findings if f["confidence"] == "HIGH")
    medium = sum(1 for f in findings if f["confidence"] == "MEDIUM")

    table = (
        TableContent(
            title=f"Comment findings for {version_id}",
            description=f"{high} HIGH, {medium} MEDIUM",
        )
        .add_column("addr", "Addr")
        .add_column("conf", "Confidence")
        .add_column("check", "Check")
        .add_column("message", "Message")
    )
    for f in sorted(findings, key=lambda x: (x["confidence"] != "HIGH", x["addr"])):
        table.add_row(
            addr=f"&{f['addr']:04X}",
            conf=f["confidence"],
            check=f["check"],
            message=f["message"],
        )
    return Reports(findings=Report(data=table))


@main.group(help="Inter-procedural call-graph queries.")
def cfg() -> None:
    pass


@cfg.command("leaves", help="List leaf subroutines (no internal callees).")
@click.argument("version_id")
@report_output(reports={"leaves": "Leaf subroutines"})
def cfg_leaves(version_id: str) -> Reports:
    ctx = click.get_current_context()
    project_context = require_project(ctx)
    files = resolve_version_files(project_context, version_id)
    if not files.json_filepath.exists():
        raise click.UsageError(
            f"JSON not found: {files.json_filepath}"
        )
    base_regions = effective_regions_for(project_context, version_id)
    if base_regions:
        import json as _json
        meta = _json.loads(files.json_filepath.read_text()).get("meta", {})
        memory_regions = build_memory_regions(meta, base_regions=base_regions)
        graph = build_call_graph(
            files.json_filepath, memory_regions=memory_regions
        )
    else:
        graph = build_call_graph(files.json_filepath)

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
    ctx = click.get_current_context()
    project_context = require_project(ctx)
    files = resolve_version_files(project_context, version_id)
    if not files.json_filepath.exists():
        raise click.UsageError(
            f"JSON not found: {files.json_filepath}"
        )
    base_regions = effective_regions_for(project_context, version_id)
    if base_regions:
        import json as _json
        meta = _json.loads(files.json_filepath.read_text()).get("meta", {})
        memory_regions = build_memory_regions(meta, base_regions=base_regions)
        graph = build_call_graph(
            files.json_filepath, memory_regions=memory_regions
        )
    else:
        graph = build_call_graph(files.json_filepath)

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
    ctx = click.get_current_context()
    project_context = require_project(ctx)
    files = resolve_version_files(project_context, version_id)
    if not files.json_filepath.exists():
        raise click.UsageError(
            f"JSON not found: {files.json_filepath}"
        )
    base_regions = effective_regions_for(project_context, version_id)
    if base_regions:
        import json as _json
        meta = _json.loads(files.json_filepath.read_text()).get("meta", {})
        memory_regions = build_memory_regions(meta, base_regions=base_regions)
        graph = build_call_graph(
            files.json_filepath, memory_regions=memory_regions
        )
    else:
        graph = build_call_graph(files.json_filepath)
    depths = compute_call_depths(graph)

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
    ctx = click.get_current_context()
    project_context = require_project(ctx)
    files = resolve_version_files(project_context, version_id)
    if not files.json_filepath.exists():
        raise click.UsageError(
            f"JSON not found: {files.json_filepath}"
        )
    base_regions = effective_regions_for(project_context, version_id)
    if base_regions:
        import json as _json
        meta = _json.loads(files.json_filepath.read_text()).get("meta", {})
        memory_regions = build_memory_regions(meta, base_regions=base_regions)
        graph = build_call_graph(
            files.json_filepath, memory_regions=memory_regions
        )
    else:
        graph = build_call_graph(files.json_filepath)
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


@main.group(help="Assembly-source extraction and inspection.")
def asm() -> None:
    pass


@asm.command(
    "extract",
    help=(
        "Extract a section of the version's .asm file by address or "
        "label, with line numbers."
    ),
)
@click.argument("version_id")
@click.argument("start_target")
@click.argument("end_target", required=False)
@click.option(
    "--window",
    type=click.IntRange(1, 1000),
    default=40,
    show_default=True,
    help="Default lines to capture when no end target is given.",
)
@click.pass_context
def asm_extract_cmd(
    ctx: click.Context,
    version_id: str,
    start_target: str,
    end_target: str | None,
    window: int,
) -> None:
    project_context = require_project(ctx)
    files = resolve_version_files(project_context, version_id)
    if not files.asm_filepath.exists():
        raise click.UsageError(
            f"ASM not found: {files.asm_filepath} (run disassemble first)"
        )

    asm_lines = files.asm_filepath.read_text().splitlines(keepends=True)
    try:
        section = extract_section(
            asm_lines, start_target, end_target, default_window=window
        )
    except LookupError as exc:
        raise click.UsageError(str(exc)) from exc

    for offset, text in enumerate(section.lines):
        click.echo(
            f"{section.start_line + offset + 1:5d}  {text}", nl=False
        )


@main.command(
    "shared",
    help=(
        "Find shared 6502 code fragments between a primary ROM and "
        "one or more reference ROMs. Specs use the form "
        "[label=]path@load-addr (e.g. nfs=path/to/nfs.rom@&8000)."
    ),
)
@click.argument("primary")
@click.argument("references", nargs=-1, required=True)
@click.option(
    "--min-len",
    type=click.IntRange(1, 1000),
    default=8,
    show_default=True,
    help="Minimum matching span length, in instructions.",
)
@click.option(
    "--limit",
    type=click.IntRange(1, 1000),
    default=None,
    help="Show at most N longest matches per reference.",
)
@report_output(reports={"matches": "Shared code spans"})
def shared(
    primary: str,
    references: tuple[str, ...],
    min_len: int,
    limit: int | None,
) -> Reports:
    try:
        p_label, p_path, p_base = parse_rom_spec(primary)
    except (ValueError, FileNotFoundError) as exc:
        raise click.UsageError(str(exc)) from exc

    primary_rom = load_rom(p_label, p_path, p_base)

    table = (
        TableContent(
            title=f"Shared spans against {primary_rom.label}",
            description=(
                f"{len(primary_rom.data)} bytes @ &{primary_rom.load_addr:04X}"
            ),
        )
        .add_column("reference", "Reference")
        .add_column("size", "Instr")
        .add_column("bytes", "Bytes")
        .add_column("primary", "Primary addr")
        .add_column("ref", "Reference addr")
    )

    for spec in references:
        try:
            r_label, r_path, r_base = parse_rom_spec(spec)
        except (ValueError, FileNotFoundError) as exc:
            raise click.UsageError(str(exc)) from exc
        reference = load_rom(r_label, r_path, r_base)
        matches = find_matching_spans(primary_rom, reference, min_len)
        matches.sort(key=lambda m: -m[2])
        if limit is not None:
            matches = matches[:limit]
        for a_idx, b_idx, size in matches:
            a_addr = primary_rom.runtime_addr(a_idx)
            b_addr = reference.runtime_addr(b_idx)
            a_off = primary_rom.instructions[a_idx].offset
            a_end_idx = a_idx + size
            a_end_off = (
                primary_rom.instructions[a_end_idx].offset
                if a_end_idx < len(primary_rom.instructions)
                else len(primary_rom.data)
            )
            span_bytes = a_end_off - a_off
            table.add_row(
                reference=r_label,
                size=str(size),
                bytes=str(span_bytes),
                primary=f"&{a_addr:04X}",
                ref=f"&{b_addr:04X}",
            )

    return Reports(matches=Report(data=table))


@main.group(help="Auto-generated label classification and renaming.")
def labels() -> None:
    pass


@labels.command(
    "classify",
    help=(
        "Classify auto-generated labels (c#### / l#### / loop_c#### / "
        "sub_c####) into categories: subroutine, shared_tail, data, "
        "internal_loop, internal_conditional."
    ),
)
@click.argument("version_id")
@click.option(
    "--category",
    type=click.Choice(
        ["subroutine", "shared_tail", "data", "internal_loop", "internal_conditional"],
        case_sensitive=False,
    ),
    help="Restrict to one category.",
)
@report_output(reports={"labels": "Auto-label classification"})
def labels_classify(version_id: str, category: str | None) -> Reports:
    import json as _json

    from .api.audit import build_memory_regions, load_subroutines

    ctx = click.get_current_context()
    project_context = require_project(ctx)
    files = resolve_version_files(project_context, version_id)
    if not files.json_filepath.exists():
        raise click.UsageError(
            f"JSON not found: {files.json_filepath}"
        )

    data = _json.loads(files.json_filepath.read_text())
    items = data["items"]
    target_refs = build_target_refs(items)
    base_regions = effective_regions_for(project_context, version_id)
    memory_regions = build_memory_regions(
        data.get("meta", {}), base_regions=base_regions
    )
    audit_subs = load_subroutines(
        files.json_filepath, memory_regions=memory_regions
    )

    classified = classify_labels(
        collect_auto_labels(items),
        items,
        target_refs,
        audit_subs,
        memory_regions,
    )
    classified = sort_labels(classified)
    if category:
        classified = [c for c in classified if c["category"] == category]

    table = (
        TableContent(
            title=f"Auto-labels in {version_id}",
            description=f"{len(classified)} labels"
            + (f" in category {category}" if category else ""),
        )
        .add_column("name", "Name")
        .add_column("addr", "Addr")
        .add_column("category", "Category")
        .add_column("refs", "Refs")
        .add_column("xref", "X-sub")
        .add_column("parent", "Parent")
    )
    for record in classified:
        table.add_row(
            name=record["name"],
            addr=f"&{record['addr']:04X}",
            category=record["category"],
            refs=str(len(record["inbound_refs"])),
            xref=str(record["cross_sub_count"]),
            parent=record["parent_sub_name"] or "",
        )
    return Reports(labels=Report(data=table))


@main.command(
    "promote",
    help=(
        "Score labelled code items as candidates for promotion to "
        "entry()/subroutine() declarations."
    ),
)
@click.argument("version_id")
@click.option(
    "--threshold",
    type=click.IntRange(0, 100),
    default=25,
    show_default=True,
    help="Hide candidates below this score.",
)
@click.option(
    "--show-all",
    is_flag=True,
    help="Show every candidate regardless of score.",
)
@click.option(
    "--not-declared",
    is_flag=True,
    help="Hide labels already declared as entry/subroutine.",
)
@report_output(reports={"candidates": "Promotion candidates"})
def promote_cmd(
    version_id: str, threshold: int, show_all: bool, not_declared: bool
) -> Reports:
    ctx = click.get_current_context()
    project_context = require_project(ctx)
    files = resolve_version_files(project_context, version_id)
    if not files.json_filepath.exists():
        raise click.UsageError(
            f"JSON not found: {files.json_filepath}"
        )

    import json as _json
    candidates = analyze_labels(_json.loads(files.json_filepath.read_text()))
    if not show_all:
        candidates = [c for c in candidates if c["score"] >= threshold]
    if not_declared:
        candidates = [
            c for c in candidates
            if not c["is_entry"] and not c["is_subroutine"]
        ]

    table = (
        TableContent(
            title=f"Promotion candidates for {version_id}",
            description=(
                f"{len(candidates)} candidates"
                + ("" if show_all else f", score ≥ {threshold}")
            ),
        )
        .add_column("addr", "Addr")
        .add_column("score", "Score")
        .add_column("name", "Name")
        .add_column("refs", "Refs")
        .add_column("jsr", "JSR")
        .add_column("after_term", "AfterTerm")
        .add_column("entry", "Entry")
        .add_column("sub", "Sub")
    )
    for c in candidates:
        table.add_row(
            addr=f"&{c['addr']:04X}",
            score=f"{c['score']:.0f}",
            name=c["name"],
            refs=str(c["total_refs"]),
            jsr=str(c["jsr_refs"]),
            after_term="Y" if c["after_terminal"] else "",
            entry="Y" if c["is_entry"] else "",
            sub="Y" if c["is_subroutine"] else "",
        )
    return Reports(candidates=Report(data=table))


@main.command(
    "fingerprint",
    help=(
        "Fingerprint each block of a ROM version's bytes and report any "
        "duplicate blocks (a quick cross-check for relocated code)."
    ),
)
@click.argument("version_id")
@click.option(
    "--block-size",
    type=click.IntRange(1, 4096),
    default=64,
    show_default=True,
    help="Block size in bytes.",
)
@click.option(
    "--cpu",
    default="6502",
    show_default=True,
    help='CPU for opcode lengths: "6502" or "65c02".',
)
@click.option(
    "--rom-base",
    type=click.IntRange(0, 0xFFFF),
    default=0x8000,
    show_default=True,
    help="ROM load address.",
)
@report_output(reports={"duplicates": "Duplicate blocks"})
def fingerprint_cmd(
    version_id: str, block_size: int, cpu: str, rom_base: int
) -> Reports:
    ctx = click.get_current_context()
    project_context = require_project(ctx)
    files = resolve_version_files(project_context, version_id)
    if not files.rom_filepath.exists():
        raise click.UsageError(
            f"ROM not found: {files.rom_filepath}"
        )

    fps = fingerprint_blocks(
        files.rom_filepath.read_bytes(),
        block_size=block_size,
        cpu=cpu,
        rom_base=rom_base,
    )
    duplicates = find_duplicate_blocks(fps)

    table = (
        TableContent(
            title=f"Duplicate blocks in {version_id}",
            description=(
                f"{len(duplicates)} duplicate fingerprints "
                f"out of {len(fps)} blocks"
            ),
        )
        .add_column("fingerprint", "Fingerprint")
        .add_column("count", "Count")
        .add_column("addresses", "Addresses")
    )
    for fp, addrs in sorted(duplicates.items(), key=lambda x: -len(x[1])):
        table.add_row(
            fingerprint=fp,
            count=str(len(addrs)),
            addresses=", ".join(f"&{a:04X}" for a in addrs),
        )
    return Reports(duplicates=Report(data=table))


@main.group(help="Subroutine workflow helpers.")
def sub() -> None:
    pass


@sub.command(
    "insert",
    help=(
        "Find where a new subroutine() declaration for ADDRESS belongs "
        "in the given driver script (address-sorted insertion)."
    ),
)
@click.argument("driver_filepath", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("address")
@report_output(reports={"insert": "Insertion point"})
def sub_insert(driver_filepath: Path, address: str) -> Reports:
    cleaned = address.strip().lstrip("$&").removeprefix("0x")
    try:
        target_addr = int(cleaned, 16)
    except ValueError as exc:
        raise click.UsageError(f"invalid address {address!r}") from exc

    lines = driver_filepath.read_text().splitlines()
    try:
        ip = compute_insert_point(lines, target_addr)
    except AlreadyDeclared as exc:
        raise click.UsageError(str(exc)) from exc
    except LookupError as exc:
        raise click.UsageError(str(exc)) from exc

    table = (
        TableContent(
            title=f"Insertion point for &{target_addr:04X}",
            description=str(driver_filepath),
        )
        .add_column("key", "Key")
        .add_column("value", "Value")
        .add_row(key="insert_line", value=str(ip.insert_line + 1))
        .add_row(
            key="predecessor",
            value=(
                f"&{ip.predecessor['addr']:04X} {ip.predecessor['name'] or ''} "
                f"(line {ip.predecessor['start_line'] + 1})"
                if ip.predecessor
                else "(start of block)"
            ),
        )
        .add_row(
            key="successor",
            value=(
                f"&{ip.successor['addr']:04X} {ip.successor['name'] or ''} "
                f"(line {ip.successor['start_line'] + 1})"
                if ip.successor
                else "(end of block)"
            ),
        )
        .add_row(
            key="block",
            value=f"lines {ip.block_start_line + 1}-{ip.block_end_line + 1}",
        )
    )
    return Reports(insert=Report(data=table))


@main.command(
    "lint",
    help=(
        "Validate that a driver script's annotation addresses "
        "(comment / subroutine / label) all map to addresses present "
        "in the version's disassembly output."
    ),
)
@click.argument("version_id")
@click.argument(
    "driver_filepath",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@report_output(reports={"unmapped": "Annotations whose addresses are not in the disassembly"})
def lint_annotations(
    version_id: str, driver_filepath: Path
) -> Reports:
    import json as _json

    ctx = click.get_current_context()
    project_context = require_project(ctx)
    files = resolve_version_files(project_context, version_id)
    if not files.json_filepath.exists():
        raise click.UsageError(
            f"JSON not found: {files.json_filepath}"
        )

    data = _json.loads(files.json_filepath.read_text())
    base_regions = effective_regions_for(project_context, version_id)
    ranges = address_ranges_from_data(data, base_regions=base_regions)
    annotations = extract_annotations(driver_filepath.read_text())

    unmapped = [
        a for a in annotations
        if a.get("detail") != "metadata_only"
        and not address_in_ranges(a["address"], ranges)
    ]

    table = (
        TableContent(
            title=f"Lint findings for {version_id}",
            description=(
                f"{len(unmapped)} unmapped annotations "
                f"of {len(annotations)} total"
            ),
        )
        .add_column("addr", "Addr")
        .add_column("kind", "Kind")
        .add_column("name", "Name")
        .add_column("line", "Line")
    )
    for ann in sorted(unmapped, key=lambda a: (a["address"], a["line_number"])):
        table.add_row(
            addr=f"&{ann['address']:04X}",
            kind=ann["kind"],
            name=ann.get("name") or "",
            line=str(ann["line_number"]),
        )
    return Reports(unmapped=Report(data=table))


@main.command(
    "backfill",
    help=(
        "Propose annotation propagations from SOURCE_VERSION to "
        "TARGET_VERSION via the project's version graph. Walks the "
        "shortest path between the two versions, builds a per-hop "
        "opcode-level confidence map, composes them with min-confidence, "
        "and reports source-driver annotations (comments / labels / "
        "subroutines) that map to target addresses above THRESHOLD and "
        "don't conflict with annotations already in the target driver. "
        "First-pass output is report-only — copy the suggested lines "
        "into the target driver yourself."
    ),
)
@click.argument("source_version")
@click.argument("target_version")
@click.argument(
    "source_driver",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.argument(
    "target_driver",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--threshold",
    type=click.IntRange(1, 1000),
    default=5,
    show_default=True,
    help="Minimum composed block_length to accept a propagation.",
)
@click.option(
    "--cpu",
    default="6502",
    show_default=True,
    help='CPU for opcode lengths: "6502" or "65c02".',
)
@click.option(
    "--rom-base",
    type=click.IntRange(0, 0xFFFF),
    default=0x8000,
    show_default=True,
    help="ROM load address (used for confidence-map address arithmetic).",
)
@report_output(reports={"candidates": "Backfill propagation candidates"})
def backfill_cmd(
    source_version: str,
    target_version: str,
    source_driver: Path,
    target_driver: Path,
    threshold: int,
    cpu: str,
    rom_base: int,
) -> Reports:
    ctx = click.get_current_context()
    project_context = require_project(ctx)

    try:
        graph = load_version_graph(project_context)
    except VersionGraphError as exc:
        raise click.UsageError(
            f"version graph could not be loaded: {exc}"
        ) from exc

    if len(graph) == 0:
        raise click.UsageError(
            "no [[versions.entry]] entries in fantasm.toml; backfill "
            "needs the version graph to walk between versions"
        )

    # ROM loader: caches each version's bytes after the first load.
    rom_cache: dict[str, bytes] = {}

    def loader(version_id: str) -> bytes:
        if version_id not in rom_cache:
            files = resolve_version_files(project_context, version_id)
            if not files.rom_filepath.exists():
                raise click.UsageError(
                    f"ROM not found: {files.rom_filepath}"
                )
            rom_cache[version_id] = files.rom_filepath.read_bytes()
        return rom_cache[version_id]

    try:
        confidence_map = compose_chained_map(
            graph,
            source_version,
            target_version,
            loader,
            rom_base=rom_base,
            cpu=cpu,
        )
    except VersionNotInGraphError as exc:
        raise click.UsageError(
            f"{exc}; add a [[versions.entry]] block for it"
        ) from exc
    except NoPathError as exc:
        raise click.UsageError(str(exc)) from exc

    path = graph.find_path(source_version, target_version)
    propagation = propose_propagations(
        source_driver.read_text(),
        target_driver.read_text(),
        confidence_map,
        threshold=threshold,
    )

    table = (
        TableContent(
            title=f"Backfill {source_version} → {target_version}",
            description=(
                f"path: {len(path)} hop(s); "
                f"{len(propagation.candidates)} candidates above threshold "
                f"{threshold}; "
                f"skipped: {propagation.skipped_no_mapping} no-mapping, "
                f"{propagation.skipped_below_threshold} below-threshold, "
                f"{propagation.skipped_target_has_annotation} target-has-anno, "
                f"{propagation.skipped_label_name_conflict} label-conflict"
            ),
        )
        .add_column("src", "Source")
        .add_column("tgt", "Target")
        .add_column("conf", "Conf")
        .add_column("kind", "Kind")
        .add_column("name", "Name")
        .add_column("text", "Text")
    )
    for candidate in propagation.candidates:
        if candidate.kind == "subroutine":
            preview = candidate.text.split("\n")[0]
            if "\n" in candidate.text:
                preview += " …"
        else:
            preview = candidate.text
        table.add_row(
            src=f"&{candidate.source_addr:04X}",
            tgt=f"&{candidate.target_addr:04X}",
            conf=str(candidate.confidence),
            kind=candidate.kind,
            name=candidate.name or "",
            text=preview,
        )
    return Reports(candidates=Report(data=table))


@main.group(help="Initialise and manage fantasm projects.")
def project() -> None:
    pass


@project.command(
    "init",
    help=(
        "Initialise a fantasm project (write fantasm.toml, create the "
        "versions directory). Safe to run inside an existing repository: "
        "no existing files are touched apart from fantasm.toml."
    ),
)
@click.option("--name", required=True, help="Project name.")
@click.option(
    "--prefix",
    "prefixes",
    multiple=True,
    help=(
        "ROM-name prefix. Repeat for multi-prefix projects (e.g. NFS's "
        "anfs/nfs). Defaults to the project name when omitted."
    ),
)
@click.option(
    "--at",
    "at_dirpath",
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    default=Path("."),
    show_default=True,
    help="Project root directory. Created if absent.",
)
@click.option(
    "--cpu",
    default="6502",
    show_default=True,
    help='Default CPU for opcode decode: "6502" / "65c02".',
)
@click.option(
    "--versions-dir",
    "versions_dirname",
    default="versions",
    show_default=True,
    help="Subdirectory holding ROM-version directories.",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite fantasm.toml if it already exists.",
)
def project_init(
    name: str,
    prefixes: tuple[str, ...],
    at_dirpath: Path,
    cpu: str,
    versions_dirname: str,
    force: bool,
) -> None:
    if not prefixes:
        prefixes = (name,)
    try:
        config = ProjectInitConfig(
            name=name,
            prefixes=prefixes,
            cpu=cpu,
            versions_dirname=versions_dirname,
        )
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    try:
        toml_filepath = init_project(at_dirpath, config, force=force)
    except FileExistsError as exc:
        raise click.UsageError(str(exc)) from exc
    click.echo(f"Wrote {toml_filepath}")
    click.echo(
        f"Versions directory: {at_dirpath / versions_dirname}"
    )


@project.command(
    "add",
    help=(
        "Create a new ROM-version directory under the project. Builds "
        "{versions}/{prefix}-{version_id}/ with rom/ and output/ "
        "subdirectories ready for ROM bytes and disassembly artefacts."
    ),
)
@click.argument("version_id")
@click.option(
    "--prefix",
    help=(
        "Prefix to use for the new version directory. Defaults to the "
        "first prefix in [versions] prefixes."
    ),
)
@click.pass_context
def project_add(
    ctx: click.Context, version_id: str, prefix: str | None
) -> None:
    project_context: ProjectContext = ctx.obj["project"]
    if not project_context.has_root:
        raise click.UsageError(
            "no project root resolved; pass --project-root, set "
            "FANTASM_PROJECT_ROOT, or run from inside a fantasm project"
        )
    versions_dirpath = project_versions_dirpath(project_context)
    if prefix is None:
        configured_prefixes = project_rom_prefixes(project_context)
        if not configured_prefixes:
            raise click.UsageError(
                "no prefix configured; pass --prefix or set "
                "[versions] prefixes in fantasm.toml"
            )
        prefix = configured_prefixes[0]
    try:
        version_dirpath = add_version(versions_dirpath, version_id, prefix)
    except (FileExistsError, ValueError) as exc:
        raise click.UsageError(str(exc)) from exc
    click.echo(f"Created {version_dirpath}")
    click.echo(f"  rom/    (drop the ROM bytes here)")
    click.echo(f"  output/ (disassembly artefacts go here)")


@project.command("list", help="List ROM versions registered in the project.")
@report_output(reports={"versions": "ROM versions in this project"})
def project_list() -> Reports:
    project_context: ProjectContext = click.get_current_context().obj["project"]
    table = (
        TableContent(
            title="ROM versions",
            description=(
                str(project_context.root_dirpath)
                if project_context.has_root
                else "(no project root resolved)"
            ),
        )
        .add_column("prefix", "Prefix")
        .add_column("version", "Version")
        .add_column("dirpath", "Path")
    )
    if project_context.has_root:
        versions_dirpath = project_versions_dirpath(project_context)
        prefixes = project_rom_prefixes(project_context)
        for info in list_versions(versions_dirpath, prefixes):
            table.add_row(
                prefix=info.prefix,
                version=info.version_id,
                dirpath=str(info.dirpath),
            )
    return Reports(versions=Report(data=table))


if __name__ == "__main__":  # pragma: no cover
    main()
