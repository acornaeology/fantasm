"""``fantasm annotations`` — cross-version annotation diff."""

from __future__ import annotations

from pathlib import Path

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from ..api.backfill import diff_annotations
from ..api.version_graph import (
    NoPathError,
    VersionGraphError,
    VersionNotInGraphError,
    compose_chained_map,
    load_version_graph,
)
from ..cli_helpers import (
    make_binary_loader,
    project_cpu,
    project_binary_base,
    require_project,
    resolve_version_files,
)
from ._options import cpu_option, rom_base_option


@click.group(help="Cross-version annotation diff and management.")
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
@cpu_option
@rom_base_option
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
        rom_base = project_binary_base(project_context)

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

    loader = make_binary_loader(project_context)

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
