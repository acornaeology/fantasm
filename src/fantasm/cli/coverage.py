"""``fantasm coverage`` — global inline-comment coverage snapshot.

Aggregate counterpart to :mod:`fantasm.cli.context` — where
``context uncommented`` filters subroutines below a density
threshold, ``coverage`` answers the headline question "what's the
inline-comment density across the ROM right now?" with one number,
plus an optional per-page or per-subroutine breakdown.
"""

from __future__ import annotations

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from ..api.context import compute_coverage
from ..cli_helpers import analysis_context


_BY_CHOICES = ("page", "sub")


@click.command(
    "coverage",
    help=(
        "Report the disassembly's inline-comment coverage as a single "
        "headline percentage (commented code items / total code items) "
        "plus the supporting counts. Pass --by page for a per-256-byte "
        "breakdown or --by sub for a per-subroutine breakdown."
    ),
)
@click.argument("version_id")
@click.option(
    "--by",
    "group_by",
    type=click.Choice(_BY_CHOICES, case_sensitive=False),
    default=None,
    help="Group the breakdown by ROM page (256 bytes) or by subroutine.",
)
@report_output(reports={
    "summary": "Headline coverage and supporting counts",
    "groups": "Per-page or per-subroutine breakdown (only with --by)",
})
def coverage(version_id: str, group_by: str | None) -> Reports:
    actx = analysis_context(click.get_current_context(), version_id)
    audit_subs = actx.audit_subs if group_by == "sub" else None
    report = compute_coverage(
        actx.data, audit_subs=audit_subs, group_by=group_by
    )

    summary = (
        TableContent(
            title=f"Coverage for {version_id}",
            description=(
                f"{report.percentage:.1f}% inline-comment density across "
                f"{report.code_count} code items in "
                f"{report.subroutine_count} subroutines"
            ),
        )
        .add_column("metric", "Metric")
        .add_column("value", "Value")
        .add_row(metric="density", value=f"{report.percentage:.1f}%")
        .add_row(metric="commented", value=str(report.commented_count))
        .add_row(metric="code_items", value=str(report.code_count))
        .add_row(metric="subroutines", value=str(report.subroutine_count))
    )

    groups_table = (
        TableContent(
            title=(
                f"Coverage by {group_by}"
                if group_by
                else "Coverage breakdown"
            ),
            description=f"{len(report.groups)} groups",
        )
        .add_column("range", "Range" if group_by == "page" else "Sub")
        .add_column("addr", "Addr")
        .add_column("code", "Code")
        .add_column("commented", "Commented")
        .add_column("density", "Density")
    )
    for group in report.groups:
        groups_table.add_row(
            range=group.label,
            addr=f"&{group.start_addr:04X}",
            code=str(group.code_count),
            commented=str(group.commented_count),
            density=f"{group.percentage:.1f}%",
        )

    return Reports(
        summary=Report(data=summary),
        groups=Report(data=groups_table),
    )
