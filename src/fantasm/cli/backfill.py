"""``fantasm backfill`` — propagate annotations across versions."""

from __future__ import annotations

from pathlib import Path

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from ..api.backfill import propose_propagations
from ..api.version_graph import (
    NoPathError,
    VersionGraphError,
    VersionNotInGraphError,
    compose_chained_map,
    load_version_graph,
)
from ..cli_helpers import (
    make_rom_loader,
    project_cpu,
    project_rom_base,
    require_project,
    resolve_version_files,
)
from ._options import cpu_option, rom_base_option


@click.command(
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
@cpu_option
@rom_base_option
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

    loader = make_rom_loader(project_context)

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
