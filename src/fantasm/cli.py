"""Click-based command-line entrypoint for fantasm."""

from __future__ import annotations

from pathlib import Path

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from . import __version__
from .api.asm_extract import extract_section
from .api.backfill import (
    compose_chained_map,
    diff_annotations,
    propose_propagations,
)
from .api.audit import (
    ALL_FLAGS,
    end_type,
    find_sub,
    find_undeclared_subs,
    load_subroutines,
)
from .api.audit import build_memory_regions
from .api.cfg import build_call_graph, find_basic_blocks, resolve_sub_node
from .api.comment_check import run_checks
from .api.compare import compare_roms
from .api.context import (
    analyse_uncommented_subs,
    compute_call_depths,
    extract_sub_context,
)
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
from .api.rename_labels import apply_renames_to_lines
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
    project_cpu,
    project_rom_base,
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
        "beebasm and compare bytes to the original ROM. Pass --all "
        "to verify every version registered in the project's "
        "versions/ directory."
    ),
)
@click.argument("version_id", required=False)
@click.option(
    "--all",
    "verify_all",
    is_flag=True,
    help="Verify every version under the project's versions/ directory.",
)
@click.pass_context
def verify(
    ctx: click.Context, version_id: str | None, verify_all: bool
) -> None:
    project_context = require_project(ctx)

    if verify_all and version_id is not None:
        raise click.UsageError(
            "pass either VERSION_ID or --all, not both"
        )
    if not verify_all and version_id is None:
        raise click.UsageError("provide VERSION_ID or --all")

    if verify_all:
        from .api.paths import (
            project_rom_prefixes,
            project_versions_dirpath,
        )
        from .api.project import list_versions

        versions_dirpath = project_versions_dirpath(project_context)
        prefixes = project_rom_prefixes(project_context)
        if not prefixes:
            raise click.UsageError(
                "no [versions] prefixes configured in fantasm.toml"
            )
        infos = list_versions(versions_dirpath, prefixes)
        if not infos:
            raise click.UsageError(
                f"no versions found under {versions_dirpath}"
            )

        passes = 0
        failures = 0
        for info in infos:
            files = resolve_version_files(project_context, info.version_id)
            if not files.rom_filepath.exists() or not files.asm_filepath.exists():
                click.echo(
                    f"{info.version_id}: SKIPPED (missing rom or asm)",
                    err=True,
                )
                failures += 1
                continue
            try:
                result = verify_round_trip(
                    files.rom_filepath, files.asm_filepath
                )
            except BeebasmNotFoundError as exc:
                raise click.UsageError(str(exc)) from exc
            if result.matched:
                click.echo(
                    f"{info.version_id}: PASSED ({result.rom_size} bytes)"
                )
                passes += 1
            else:
                if result.first_diff_offset is not None:
                    detail = f"first_diff=&{result.first_diff_offset:04X}"
                else:
                    detail = "(beebasm error)"
                click.echo(
                    f"{info.version_id}: FAILED rom={result.rom_size}b "
                    f"assembled={result.assembled_size}b {detail}",
                    err=True,
                )
                failures += 1
        click.echo(f"\n{passes} passed, {failures} failed")
        if failures:
            ctx.exit(1)
        return

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
    default=None,
    help='CPU override; defaults to [rom] cpu in fantasm.toml (or "6502").',
)
@click.option(
    "--rom-base",
    type=click.IntRange(0, 0xFFFF),
    default=None,
    help="ROM load address; defaults to [rom] base_address (or 0x8000).",
)
@click.pass_context
def compare(
    ctx: click.Context,
    version_a: str,
    version_b: str,
    cpu: str | None,
    rom_base: int | None,
) -> None:
    project_context = require_project(ctx)
    if cpu is None:
        cpu = project_cpu(project_context)
    if rom_base is None:
        rom_base = project_rom_base(project_context)
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
    "detail",
    help="Show the full audit report for one subroutine.",
)
@click.argument("version_id")
@click.argument("target")
@report_output(reports={
    "info": "Subroutine summary",
    "called_by": "Direct callers (JSR/JMP)",
    "branch_entries": "Branch entries",
    "escaping_branches": "Branches that leave the sub",
})
def audit_detail(version_id: str, target: str) -> Reports:
    import json as _json

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

    sub = find_sub(subs, target)
    if sub is None:
        raise click.UsageError(
            f"subroutine {target!r} not found in {version_id}"
        )

    end_label = end_type(sub)
    range_str = (
        f"&{sub['items'][0]['addr']:04X}-&{sub['items'][-1]['addr']:04X}"
        if sub["items"]
        else "(empty)"
    )
    info = (
        TableContent(
            title=f"{sub['name']} (&{sub['addr']:04X})",
            description=sub["title"] or "(no title)",
        )
        .add_column("key", "Key")
        .add_column("value", "Value")
        .add_row(key="address", value=f"&{sub['addr']:04X}")
        .add_row(key="name", value=sub["name"])
        .add_row(key="title", value=sub["title"] or "")
        .add_row(key="end_type", value=end_label)
        .add_row(key="extent", value=range_str)
        .add_row(
            key="items",
            value=f"{sub['code_count']} code / {sub['data_count']} data",
        )
        .add_row(
            key="flags",
            value=", ".join(sorted(sub["flags"])) if sub["flags"] else "",
        )
        .add_row(key="description", value=sub["description"] or "")
    )

    callers = (
        TableContent(title=f"Callers of {sub['name']}")
        .add_column("addr", "Addr")
        .add_column("mnemonic", "Op")
        .add_column("in_sub", "In subroutine")
    )
    for ref in sorted(sub["entry_refs"], key=lambda r: r["addr"]):
        callers.add_row(
            addr=f"&{ref['addr']:04X}",
            mnemonic=ref["mnemonic"].upper(),
            in_sub=ref["in_sub"],
        )

    branches = (
        TableContent(title=f"Branch entries to {sub['name']}")
        .add_column("addr", "Addr")
        .add_column("mnemonic", "Op")
        .add_column("in_sub", "In subroutine")
    )
    for ref in sorted(sub["branch_entry_refs"], key=lambda r: r["addr"]):
        branches.add_row(
            addr=f"&{ref['addr']:04X}",
            mnemonic=ref["mnemonic"].upper(),
            in_sub=ref["in_sub"],
        )

    escaping = (
        TableContent(title=f"Branches escaping {sub['name']}")
        .add_column("addr", "Addr")
        .add_column("mnemonic", "Op")
        .add_column("target", "Target")
    )
    for br in sorted(sub["escaping_branches"], key=lambda b: b["addr"]):
        escaping.add_row(
            addr=f"&{br['addr']:04X}",
            mnemonic=br["mnemonic"].upper(),
            target=f"&{br['target']:04X} {br['target_label']}",
        )

    return Reports(
        info=Report(data=info),
        called_by=Report(data=callers),
        branch_entries=Report(data=branches),
        escaping_branches=Report(data=escaping),
    )


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
    import json as _json

    ctx = click.get_current_context()
    project_context = require_project(ctx)
    files = resolve_version_files(project_context, version_id)
    if not files.json_filepath.exists():
        raise click.UsageError(
            f"JSON not found: {files.json_filepath}"
        )

    base_regions = effective_regions_for(project_context, version_id)
    data = _json.loads(files.json_filepath.read_text())
    memory_regions = build_memory_regions(
        data["meta"], base_regions=base_regions
    )

    if sub_target is None:
        items = data["items"]
        sub_label = "(all subroutines)"
    else:
        audit_subs = load_subroutines(
            files.json_filepath, memory_regions=memory_regions
        )
        sub = find_sub(audit_subs, sub_target)
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
    import json as _json

    ctx = click.get_current_context()
    project_context = require_project(ctx)
    files = resolve_version_files(project_context, version_id)
    if not files.json_filepath.exists():
        raise click.UsageError(
            f"JSON not found: {files.json_filepath}"
        )
    if not files.asm_filepath.exists():
        raise click.UsageError(
            f"ASM not found: {files.asm_filepath}"
        )

    base_regions = effective_regions_for(project_context, version_id)
    data = _json.loads(files.json_filepath.read_text())
    memory_regions = build_memory_regions(
        data["meta"], base_regions=base_regions
    )
    audit_subs = load_subroutines(
        files.json_filepath, memory_regions=memory_regions
    )
    sub = find_sub(audit_subs, target)
    if sub is None:
        raise click.UsageError(
            f"subroutine {target!r} not found in {version_id}"
        )

    if base_regions:
        graph = build_call_graph(
            files.json_filepath, memory_regions=memory_regions
        )
    else:
        graph = build_call_graph(files.json_filepath)

    asm_lines = files.asm_filepath.read_text().splitlines(keepends=True)
    sub_context = extract_sub_context(
        sub, asm_lines, graph,
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


@main.group(help="Code context queries (depth, sub-context, uncommented gaps).")
def context() -> None:
    pass


@context.command(
    "uncommented",
    help=(
        "Find subroutines below a comment-density threshold and "
        "report named callees + workspace label references. Useful "
        "for inferring the purpose of unannotated code from its "
        "relationships with already-understood code."
    ),
)
@click.argument("version_id")
@click.option(
    "--threshold-pct",
    type=click.FloatRange(0, 100),
    default=30.0,
    show_default=True,
    help="Density threshold; subs at or above this are skipped.",
)
@click.option(
    "--min-items",
    type=click.IntRange(1, 1000),
    default=20,
    show_default=True,
    help="Minimum code-item count for a sub to be considered.",
)
@click.option(
    "--label-pattern",
    "label_patterns",
    multiple=True,
    help=(
        "Substring to match against item labels for the "
        '"workspace_refs" column. Repeatable. Common BBC patterns: '
        "wksp_, fsm_, zp_, nmi_."
    ),
)
@report_output(reports={"uncommented": "Subroutines with low comment density"})
def context_uncommented(
    version_id: str,
    threshold_pct: float,
    min_items: int,
    label_patterns: tuple[str, ...],
) -> Reports:
    import json as _json

    ctx = click.get_current_context()
    project_context = require_project(ctx)
    files = resolve_version_files(project_context, version_id)
    if not files.json_filepath.exists():
        raise click.UsageError(
            f"JSON not found: {files.json_filepath}"
        )

    base_regions = effective_regions_for(project_context, version_id)
    data = _json.loads(files.json_filepath.read_text())
    memory_regions = build_memory_regions(
        data["meta"], base_regions=base_regions
    )
    audit_subs = load_subroutines(
        files.json_filepath, memory_regions=memory_regions
    )

    # Build address → name lookup from subs + external labels.
    label_to_name: dict[int, str] = {
        sub["addr"]: sub["name"] for sub in audit_subs
    }
    for label_name, addr in data.get("external_labels", {}).items():
        label_to_name[addr] = label_name

    reports = analyse_uncommented_subs(
        audit_subs,
        label_to_name=label_to_name,
        workspace_label_patterns=label_patterns,
        density_threshold_pct=threshold_pct,
        min_items=min_items,
    )

    table = (
        TableContent(
            title=f"Uncommented subroutines in {version_id}",
            description=(
                f"{len(reports)} subroutines below "
                f"{threshold_pct:.0f}% density and >= {min_items} items"
            ),
        )
        .add_column("addr", "Addr")
        .add_column("name", "Name")
        .add_column("density", "Density")
        .add_column("size", "Code")
        .add_column("callees", "Named callees")
        .add_column("workspace", "Workspace refs")
    )
    for r in reports:
        table.add_row(
            addr=f"&{r.addr:04X}",
            name=r.name,
            density=f"{r.density_pct:.0f}%",
            size=str(r.total),
            callees=", ".join(r.callees[:6])
            + ("…" if len(r.callees) > 6 else ""),
            workspace=", ".join(r.workspace_refs[:6])
            + ("…" if len(r.workspace_refs) > 6 else ""),
        )
    return Reports(uncommented=Report(data=table))


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


@labels.command(
    "apply",
    help=(
        "Apply a renames TOML file to a py8dis driver script. The "
        "TOML file should declare a `renames` array of inline "
        "tables, each with `addr` (integer) and `name` (string). "
        "Writes the rewritten driver to stdout by default; pass "
        "--in-place or --output to write to a file."
    ),
)
@click.argument(
    "driver_filepath",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.argument(
    "renames_filepath",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--in-place",
    is_flag=True,
    help="Rewrite DRIVER_FILEPATH in place.",
)
@click.option(
    "--output",
    "output_filepath",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write the rewritten driver to OUTPUT instead of stdout.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show a unified diff of the changes without writing anything.",
)
def labels_apply(
    driver_filepath: Path,
    renames_filepath: Path,
    in_place: bool,
    output_filepath: Path | None,
    dry_run: bool,
) -> None:
    import difflib
    import tomllib

    if sum([in_place, output_filepath is not None, dry_run]) > 1:
        raise click.UsageError(
            "pass at most one of --in-place, --output, --dry-run"
        )

    renames_data = tomllib.loads(renames_filepath.read_text())
    rename_entries = renames_data.get("renames")
    if not rename_entries:
        raise click.UsageError(
            f"no `renames` array found in {renames_filepath}"
        )

    rename_map: dict[int, str] = {}
    for entry in rename_entries:
        if "addr" not in entry or "name" not in entry:
            raise click.UsageError(
                f"renames entry missing addr or name: {entry}"
            )
        rename_map[int(entry["addr"])] = str(entry["name"])

    original = driver_filepath.read_text()
    lines = original.splitlines(keepends=True)
    try:
        new_lines = apply_renames_to_lines(lines, rename_map)
    except LookupError as exc:
        raise click.UsageError(str(exc)) from exc

    new_text = "".join(new_lines)

    if dry_run:
        diff = difflib.unified_diff(
            original.splitlines(keepends=True),
            new_lines,
            fromfile=str(driver_filepath),
            tofile=f"{driver_filepath} (renamed)",
        )
        click.echo("".join(diff), nl=False)
        return
    if in_place:
        driver_filepath.write_text(new_text)
        click.echo(
            f"Wrote {len(rename_map)} rename(s) to {driver_filepath}"
        )
        return
    if output_filepath is not None:
        output_filepath.write_text(new_text)
        click.echo(
            f"Wrote {len(rename_map)} rename(s) to {output_filepath}"
        )
        return
    click.echo(new_text, nl=False)


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
    default=None,
    help='CPU override; defaults to [rom] cpu in fantasm.toml (or "6502").',
)
@click.option(
    "--rom-base",
    type=click.IntRange(0, 0xFFFF),
    default=None,
    help="ROM load address; defaults to [rom] base_address (or 0x8000).",
)
@report_output(reports={"duplicates": "Duplicate blocks"})
def fingerprint_cmd(
    version_id: str,
    block_size: int,
    cpu: str | None,
    rom_base: int | None,
) -> Reports:
    ctx = click.get_current_context()
    project_context = require_project(ctx)
    if cpu is None:
        cpu = project_cpu(project_context)
    if rom_base is None:
        rom_base = project_rom_base(project_context)
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
@click.option(
    "--source-driver",
    "source_driver",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help=(
        "Path to the source driver script. Defaults to the path "
        "computed from [versions] driver_dirname/driver_filename for "
        "the source version."
    ),
)
@click.option(
    "--target-driver",
    "target_driver",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help=(
        "Path to the target driver script. Defaults to the path "
        "computed from [versions] driver_dirname/driver_filename for "
        "the target version."
    ),
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
    default=None,
    help='CPU override; defaults to [rom] cpu (or "6502").',
)
@click.option(
    "--rom-base",
    type=click.IntRange(0, 0xFFFF),
    default=None,
    help="ROM load address; defaults to [rom] base_address (or 0x8000).",
)
@report_output(reports={"candidates": "Backfill propagation candidates"})
def backfill_cmd(
    source_version: str,
    target_version: str,
    source_driver: Path | None,
    target_driver: Path | None,
    threshold: int,
    cpu: str | None,
    rom_base: int | None,
) -> Reports:
    ctx = click.get_current_context()
    project_context = require_project(ctx)
    if cpu is None:
        cpu = project_cpu(project_context)
    if rom_base is None:
        rom_base = project_rom_base(project_context)

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

    if source_driver is None:
        source_driver = resolve_version_files(
            project_context, source_version
        ).driver_filepath
        if not source_driver.exists():
            raise click.UsageError(
                f"source driver not found at {source_driver}; pass "
                "--source-driver explicitly"
            )
    if target_driver is None:
        target_driver = resolve_version_files(
            project_context, target_version
        ).driver_filepath
        if not target_driver.exists():
            raise click.UsageError(
                f"target driver not found at {target_driver}; pass "
                "--target-driver explicitly"
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


@main.group(help="Address translation across ROM versions.")
def addresses() -> None:
    pass


@addresses.command(
    "map",
    help=(
        "Map addresses from SOURCE_VERSION to TARGET_VERSION via "
        "opcode-level matching. With no --addr arguments, emits the "
        "full mapping (large for real ROMs — pipe through --as tsv). "
        "With --addr, only the specified source addresses are mapped."
    ),
)
@click.argument("source_version")
@click.argument("target_version")
@click.option(
    "--addr",
    "addrs",
    multiple=True,
    help="Source address to map (hex, with or without 0x/$/&). Repeatable.",
)
@click.option(
    "--threshold",
    type=click.IntRange(1, 1000),
    default=1,
    show_default=True,
    help="Minimum block_length confidence to include in output.",
)
@click.option(
    "--cpu",
    default=None,
    help='CPU override; defaults to [rom] cpu (or "6502").',
)
@click.option(
    "--rom-base",
    type=click.IntRange(0, 0xFFFF),
    default=None,
    help="ROM load address; defaults to [rom] base_address (or 0x8000).",
)
@click.option(
    "--include-supplementary/--primary-only",
    default=True,
    show_default=True,
    help=(
        "Include the seed-and-extend supplementary mappings (catches "
        "reordered blocks the LCS misses). --primary-only restricts "
        "to the LCS-derived mappings only."
    ),
)
@report_output(reports={"map": "Source→target address mapping"})
def addresses_map(
    source_version: str,
    target_version: str,
    addrs: tuple[str, ...],
    threshold: int,
    cpu: str | None,
    rom_base: int | None,
    include_supplementary: bool,
) -> Reports:
    from .api.blockmatch import build_full_address_map

    ctx = click.get_current_context()
    project_context = require_project(ctx)
    if cpu is None:
        cpu = project_cpu(project_context)
    if rom_base is None:
        rom_base = project_rom_base(project_context)

    files_source = resolve_version_files(project_context, source_version)
    files_target = resolve_version_files(project_context, target_version)
    if not files_source.rom_filepath.exists():
        raise click.UsageError(f"ROM not found: {files_source.rom_filepath}")
    if not files_target.rom_filepath.exists():
        raise click.UsageError(f"ROM not found: {files_target.rom_filepath}")

    rom_source = files_source.rom_filepath.read_bytes()
    rom_target = files_target.rom_filepath.read_bytes()

    full_map, primary_map, supplementary_map, _blocks = build_full_address_map(
        rom_source, rom_target, cpu_a=cpu, cpu_b=cpu, rom_base=rom_base
    )

    if include_supplementary:
        addr_map = full_map
    else:
        addr_map = primary_map

    if addrs:
        # Map only the requested addresses.
        wanted: list[int] = []
        for raw in addrs:
            cleaned = raw.strip().lstrip("$&").removeprefix("0x")
            try:
                wanted.append(int(cleaned, 16))
            except ValueError as exc:
                raise click.UsageError(
                    f"invalid address {raw!r}"
                ) from exc
        rows = [(a, addr_map.get(a)) for a in wanted]
    else:
        rows = sorted(addr_map.items())

    table = (
        TableContent(
            title=f"{source_version} → {target_version}",
            description=(
                f"primary {len(primary_map)} + supplementary "
                f"{len(supplementary_map)} entries; "
                f"showing {len(rows)} row(s)"
                + ("" if include_supplementary else " (primary only)")
            ),
        )
        .add_column("source", "Source")
        .add_column("target", "Target")
        .add_column("source_method", "Via")
    )
    for source_addr, target in rows:
        if isinstance(target, tuple):
            # full_map values are int (target only); not (target, conf).
            target_addr = target[0]
        else:
            target_addr = target
        if target_addr is None:
            table.add_row(
                source=f"&{source_addr:04X}",
                target="-",
                source_method="(no mapping)",
            )
            continue
        method = "primary" if source_addr in primary_map else "supplementary"
        table.add_row(
            source=f"&{source_addr:04X}",
            target=f"&{target_addr:04X}",
            source_method=method,
        )
    return Reports(map=Report(data=table))


@main.group(help="Cross-version annotation diff and management.")
def annotations() -> None:
    pass


@annotations.command(
    "diff",
    help=(
        "Diff annotations (comment / label / subroutine) between two "
        "versions' driver scripts. Walks the version graph to map "
        "addresses across versions, then reports source-side "
        "annotations whose mapped target is missing, differs, or "
        "can't be reached."
    ),
)
@click.argument("source_version")
@click.argument("target_version")
@click.option(
    "--source-driver",
    "source_driver",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Override the auto-resolved source driver path.",
)
@click.option(
    "--target-driver",
    "target_driver",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Override the auto-resolved target driver path.",
)
@click.option(
    "--threshold",
    type=click.IntRange(1, 1000),
    default=5,
    show_default=True,
    help="Minimum address-map confidence (block_length) for a comparison.",
)
@click.option(
    "--cpu",
    default=None,
    help='CPU override; defaults to [rom] cpu (or "6502").',
)
@click.option(
    "--rom-base",
    type=click.IntRange(0, 0xFFFF),
    default=None,
    help="ROM load address; defaults to [rom] base_address (or 0x8000).",
)
@click.option(
    "--kind",
    type=click.Choice(["comment", "label", "subroutine"], case_sensitive=False),
    multiple=True,
    help="Restrict to one or more annotation kinds. Repeatable.",
)
@click.option(
    "--status",
    type=click.Choice(
        ["differs", "missing_in_target", "no_mapping"],
        case_sensitive=False,
    ),
    multiple=True,
    help="Restrict to one or more diff statuses. Repeatable.",
)
@report_output(reports={"diffs": "Annotation differences"})
def annotations_diff(
    source_version: str,
    target_version: str,
    source_driver: Path | None,
    target_driver: Path | None,
    threshold: int,
    cpu: str | None,
    rom_base: int | None,
    kind: tuple[str, ...],
    status: tuple[str, ...],
) -> Reports:
    ctx = click.get_current_context()
    project_context = require_project(ctx)
    if cpu is None:
        cpu = project_cpu(project_context)
    if rom_base is None:
        rom_base = project_rom_base(project_context)

    try:
        graph = load_version_graph(project_context)
    except VersionGraphError as exc:
        raise click.UsageError(
            f"version graph could not be loaded: {exc}"
        ) from exc
    if len(graph) == 0:
        raise click.UsageError(
            "no [[versions.entry]] entries in fantasm.toml"
        )

    if source_driver is None:
        source_driver = resolve_version_files(
            project_context, source_version
        ).driver_filepath
        if not source_driver.exists():
            raise click.UsageError(
                f"source driver not found at {source_driver}; pass "
                "--source-driver explicitly"
            )
    if target_driver is None:
        target_driver = resolve_version_files(
            project_context, target_version
        ).driver_filepath
        if not target_driver.exists():
            raise click.UsageError(
                f"target driver not found at {target_driver}; pass "
                "--target-driver explicitly"
            )

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
    except (VersionNotInGraphError, NoPathError) as exc:
        raise click.UsageError(str(exc)) from exc

    diffs = diff_annotations(
        source_driver.read_text(),
        target_driver.read_text(),
        confidence_map,
        threshold=threshold,
    )
    if kind:
        kind_set = {k.lower() for k in kind}
        diffs = [d for d in diffs if d.kind in kind_set]
    if status:
        status_set = {s.lower() for s in status}
        diffs = [d for d in diffs if d.status in status_set]

    counts = {"differs": 0, "missing_in_target": 0, "no_mapping": 0}
    for diff in diffs:
        counts[diff.status] += 1

    table = (
        TableContent(
            title=f"{source_version} vs {target_version}",
            description=(
                f"{len(diffs)} differences: "
                f"{counts['differs']} differs, "
                f"{counts['missing_in_target']} missing in target, "
                f"{counts['no_mapping']} no mapping"
            ),
        )
        .add_column("kind", "Kind")
        .add_column("status", "Status")
        .add_column("src", "Source")
        .add_column("tgt", "Target")
        .add_column("conf", "Conf")
        .add_column("source_value", "Source value")
        .add_column("target_value", "Target value")
    )
    for diff in diffs:
        table.add_row(
            kind=diff.kind,
            status=diff.status,
            src=f"&{diff.source_addr:04X}",
            tgt=(
                f"&{diff.target_addr:04X}"
                if diff.target_addr is not None
                else "-"
            ),
            conf=str(diff.confidence) if diff.confidence else "",
            source_value=diff.source_value,
            target_value=diff.target_value or "",
        )
    return Reports(diffs=Report(data=table))


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
