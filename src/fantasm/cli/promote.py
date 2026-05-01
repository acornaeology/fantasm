"""``fantasm promote`` — score labels for promotion to entry/subroutine."""

from __future__ import annotations

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from ..api.promote import analyze_labels
from ..cli_helpers import analysis_context


@click.command(
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
    actx = analysis_context(click.get_current_context(), version_id)
    candidates = analyze_labels(actx.data)
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
