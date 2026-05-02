"""``fantasm data`` — data-declaration review and reclassification.

Two subcommands:

- ``data runs`` — rank contiguous runs of same-type data items
  (``byte`` / ``word`` / ``string``) so the longest ones surface
  first. The "Phase D" annotation workflow asks "are these long
  EQUB blocks really raw bytes, or is there structure I haven't
  spotted?"; this command is the listing.
- ``data classify`` — apply the heuristic padding / string / code
  classifiers to runs of byte items, surfacing spans that *might*
  be reclassifiable as something more specific.

Both commands read directly from the JSON disassembly via
:class:`fantasm.cli_helpers.AnalysisContext`; no ROM bytes are
needed (the JSON's per-item ``bytes`` field carries the
information).
"""

from __future__ import annotations

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from ..api.data_review import (
    find_classification_candidates,
    find_data_runs,
)
from ..cli_helpers import analysis_context, project_cpu


_TYPE_CHOICES = ("byte", "word", "string")


@click.group(
    "data",
    help="Data-declaration review (runs, heuristic reclassification).",
)
def data_group() -> None:
    pass


@data_group.command(
    "runs",
    help=(
        "List contiguous runs of same-type data items "
        "(byte / word / string), longest first. The default "
        "filter shows runs of at least 8 bytes; "
        "--min-bytes adjusts."
    ),
)
@click.argument("version_id")
@click.option(
    "--min-bytes",
    type=click.IntRange(1, 0x10000),
    default=8,
    show_default=True,
    help="Minimum byte length for a run to be reported.",
)
@click.option(
    "--type",
    "type_filters",
    type=click.Choice(_TYPE_CHOICES, case_sensitive=False),
    multiple=True,
    help=(
        "Restrict to one or more item types. Repeatable "
        "(--type byte --type word). Defaults to all three."
    ),
)
@click.option(
    "--annotated/--unannotated",
    "annotated_filter",
    default=None,
    help=(
        "Show only annotated (label / inline comment) or only "
        "un-annotated runs. Default: show both."
    ),
)
@report_output(reports={"runs": "Contiguous data-item runs, longest first"})
def data_runs(
    version_id: str,
    min_bytes: int,
    type_filters: tuple[str, ...],
    annotated_filter: bool | None,
) -> Reports:
    actx = analysis_context(click.get_current_context(), version_id)

    item_types = (
        tuple(t.lower() for t in type_filters) if type_filters else _TYPE_CHOICES
    )
    runs = find_data_runs(
        actx.data["items"], min_bytes=min_bytes, item_types=item_types,
    )

    if annotated_filter is True:
        runs = [r for r in runs if r.is_annotated]
    elif annotated_filter is False:
        runs = [r for r in runs if not r.is_annotated]

    table = (
        TableContent(
            title=f"Data runs in {version_id}",
            description=(
                f"{len(runs)} runs of >= {min_bytes} bytes "
                f"(types: {', '.join(item_types)})"
            ),
        )
        .add_column("addr", "Addr")
        .add_column("type", "Type")
        .add_column("items", "Items")
        .add_column("bytes", "Bytes")
        .add_column("label", "Label")
        .add_column("annotated", "Annotated")
    )
    for run in runs:
        table.add_row(
            addr=f"&{run.start_addr:04X}",
            type=run.item_type,
            items=str(run.item_count),
            bytes=str(run.byte_length),
            label=run.label or "",
            annotated="Y" if run.is_annotated else "",
        )
    return Reports(runs=Report(data=table))


@data_group.command(
    "classify",
    help=(
        "Apply heuristic classifiers (padding / string / code) to "
        "runs of byte-typed data items, listing spans that might "
        "be reclassifiable as something more specific."
    ),
)
@click.argument("version_id")
@click.option(
    "--cpu",
    default=None,
    help='CPU override; defaults to [rom] cpu in fantasm.toml (or "6502").',
)
@click.option(
    "--target-type",
    "target_types",
    type=click.Choice(_TYPE_CHOICES, case_sensitive=False),
    multiple=True,
    help=(
        "Item types whose runs the classifiers will examine. "
        "Repeatable. Default: byte."
    ),
)
@click.option(
    "--min-string",
    type=click.IntRange(1, 1000),
    default=4,
    show_default=True,
    help="Minimum length of a printable-ASCII run to flag as string.",
)
@click.option(
    "--min-code",
    type=click.IntRange(1, 1000),
    default=8,
    show_default=True,
    help="Minimum length of a valid-opcode sweep to flag as code.",
)
@click.option(
    "--min-padding",
    type=click.IntRange(1, 1000),
    default=4,
    show_default=True,
    help="Minimum length of a repeating-pattern run to flag as padding.",
)
@report_output(reports={
    "candidates": "Reclassification candidates, longest first",
})
def data_classify(
    version_id: str,
    cpu: str | None,
    target_types: tuple[str, ...],
    min_string: int,
    min_code: int,
    min_padding: int,
) -> Reports:
    actx = analysis_context(click.get_current_context(), version_id)
    if cpu is None:
        cpu = project_cpu(actx.project)

    types = (
        tuple(t.lower() for t in target_types) if target_types else ("byte",)
    )

    candidates = find_classification_candidates(
        actx.data["items"],
        cpu=cpu,
        target_types=types,
        min_string=min_string,
        min_code=min_code,
        min_padding=min_padding,
    )

    table = (
        TableContent(
            title=f"Reclassification candidates for {version_id}",
            description=(
                f"{len(candidates)} candidates across types: "
                f"{', '.join(types)} (cpu={cpu})"
            ),
        )
        .add_column("addr", "Addr")
        .add_column("length", "Length")
        .add_column("kind", "Kind")
        .add_column("conf", "Confidence")
        .add_column("preview", "Preview")
    )
    for candidate in candidates:
        table.add_row(
            addr=f"&{candidate.addr:04X}",
            length=str(candidate.length),
            kind=candidate.kind,
            conf=f"{candidate.confidence:.2f}",
            preview=candidate.preview,
        )
    return Reports(candidates=Report(data=table))
