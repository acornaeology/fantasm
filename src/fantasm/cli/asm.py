"""``fantasm asm`` — assembly-source extraction."""

from __future__ import annotations

import click

from ..api.asm_extract import extract_section
from ..cli_helpers import analysis_context


@click.group(help="Assembly-source extraction and inspection.")
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
    actx = analysis_context(ctx, version_id)
    try:
        section = extract_section(
            actx.asm_lines, start_target, end_target, default_window=window
        )
    except LookupError as exc:
        raise click.UsageError(str(exc)) from exc

    for offset, text in enumerate(section.lines):
        click.echo(
            f"{section.start_line + offset + 1:5d}  {text}", nl=False
        )
