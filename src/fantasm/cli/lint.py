"""``fantasm lint`` — validate driver-script annotation addresses."""

from __future__ import annotations

from pathlib import Path

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from ..api.lint import (
    address_in_ranges,
    address_ranges_from_data,
    extract_annotations,
)
from ..cli_helpers import analysis_context


@click.command(
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
    actx = analysis_context(click.get_current_context(), version_id)
    ranges = address_ranges_from_data(actx.data, base_regions=actx.base_regions)
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
