"""``fantasm hooks`` — print-inline ``hook_subroutine()`` discovery.

A ``hooks`` group rather than a flat command — leaves room for
future ``hooks check`` / ``hooks list`` without re-shuffling the
CLI.
"""

from __future__ import annotations

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from ..api.hooks import (
    HookCandidate,
    find_hook_candidates,
    render_hook_subroutine_line,
)
from ..cli_helpers import analysis_context, project_cpu


@click.group(
    "hooks",
    help=(
        "hook_subroutine() discovery and review. The "
        "hook_subroutine() name is shared between dasmos and "
        "py8dis driver APIs."
    ),
)
def hooks_group() -> None:
    pass


@hooks_group.command(
    "suggest",
    help=(
        "Find JSR targets that look like unhooked print-inline "
        "helpers (stringz / stringcr / stringhi). For each call "
        "site to a candidate target, the post-call pattern is "
        "checked: a string item followed by a byte run that "
        "decodes as valid 6502 code. Targets with multiple "
        "matching call sites are reported in a paste-ready "
        "hook_subroutine() form."
    ),
)
@click.argument("version_id")
@click.option(
    "--cpu",
    default=None,
    help='CPU override; defaults to [rom] cpu in fantasm.toml (or "6502").',
)
@click.option(
    "--min-call-sites",
    type=click.IntRange(1, 1000),
    default=2,
    show_default=True,
    help="Minimum matching call sites to a target before it's reported.",
)
@click.option(
    "--min-resume-code-bytes",
    type=click.IntRange(1, 100),
    default=4,
    show_default=True,
    help=(
        "Minimum bytes of valid-6502 decode required after the "
        "post-JSR string item to count as the missing-hook "
        "signature."
    ),
)
@click.option(
    "--min-confidence",
    type=click.FloatRange(0.0, 1.0),
    default=0.5,
    show_default=True,
    help=(
        "Minimum (matching call sites / total call sites) ratio "
        "for a target to be reported. 1.0 means every call to the "
        "target matches the missing-hook pattern."
    ),
)
@report_output(reports={
    "candidates": "Hook candidates (one row per target)",
    "paste": "Paste-ready hook_subroutine() lines, one per candidate",
})
def hooks_suggest(
    version_id: str,
    cpu: str | None,
    min_call_sites: int,
    min_resume_code_bytes: int,
    min_confidence: float,
) -> Reports:
    actx = analysis_context(click.get_current_context(), version_id)
    if cpu is None:
        cpu = project_cpu(actx.project)

    candidates = find_hook_candidates(
        actx.data["items"],
        cpu=cpu,
        min_call_sites=min_call_sites,
        min_resume_code_bytes=min_resume_code_bytes,
        min_confidence=min_confidence,
    )

    candidates_table = (
        TableContent(
            title=f"Hook candidates for {version_id}",
            description=(
                f"{len(candidates)} target(s) with >= "
                f"{min_call_sites} matching call sites and "
                f">= {min_confidence:.2f} confidence"
            ),
        )
        .add_column("target", "Target")
        .add_column("label", "Label")
        .add_column("kind", "Kind")
        .add_column("matching", "Matching")
        .add_column("total", "Total")
        .add_column("confidence", "Confidence")
        .add_column("samples", "Sample strings")
    )
    for cand in candidates:
        samples = " | ".join(_truncate(s) for s in cand.sample_strings)
        candidates_table.add_row(
            target=f"&{cand.target:04X}",
            label=cand.target_label or "",
            kind=cand.hook_kind,
            matching=str(len(cand.matching_call_sites)),
            total=str(cand.total_call_sites),
            confidence=f"{cand.confidence:.2f}",
            samples=samples,
        )

    paste_table = (
        TableContent(
            title="Paste-ready hook_subroutine() lines",
            description=(
                "Replace FILL_ME with a meaningful name; "
                "<HOOK_FN> on unknown-kind rows must be filled in "
                "manually."
            ),
        )
        .add_column("line", "Line")
    )
    for cand in candidates:
        paste_table.add_row(line=render_hook_subroutine_line(cand))

    return Reports(
        candidates=Report(data=candidates_table),
        paste=Report(data=paste_table),
    )


def _truncate(text: str, *, limit: int = 24) -> str:
    """Render ``text`` for the samples column with escapes for control chars."""
    rendered = (
        text.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    )
    if len(rendered) > limit:
        return rendered[: limit - 1] + "…"
    return rendered
