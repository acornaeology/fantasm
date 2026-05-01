"""``fantasm context`` — code context queries."""

from __future__ import annotations

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from ..api.context import analyse_uncommented_subs
from ..cli_helpers import analysis_context


@click.group(help="Code context queries (depth, sub-context, uncommented gaps).")
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
        "`wksp_`, `fsm_`, `zp_`, `nmi_`."
    ),
)
@report_output(reports={"uncommented": "Subroutines with low comment density"})
def context_uncommented(
    version_id: str,
    threshold_pct: float,
    min_items: int,
    label_patterns: tuple[str, ...],
) -> Reports:
    actx = analysis_context(click.get_current_context(), version_id)
    audit_subs = actx.audit_subs

    label_to_name: dict[int, str] = {
        sub["addr"]: sub["name"] for sub in audit_subs
    }
    for label_name, addr in actx.data.get("external_labels", {}).items():
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
