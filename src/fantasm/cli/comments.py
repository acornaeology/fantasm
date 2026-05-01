"""``fantasm comments`` — comment / annotation consistency checks."""

from __future__ import annotations

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from ..api.asm_extract import parse_address
from ..api.comment_check import run_checks
from ..api.suggest import suggest_comments
from ..cli_helpers import analysis_context


@click.group(help="Comment / annotation consistency checks.")
def comments() -> None:
    pass


@comments.command(
    "suggest",
    help=(
        "Generate pattern-based comment suggestions for uncommented "
        "code items. Combines generic 6502 instruction-pattern "
        "heuristics (PHA → 'Save A on stack', etc.) with "
        "project-specific workspace label hints from "
        "[comments.suggest.label_hints] in fantasm.toml. The "
        "rendered py_line column is paste-ready Python for the "
        "driver script."
    ),
)
@click.argument("version_id")
@click.option(
    "--start",
    "start_addr",
    help="Start address (hex, inclusive). Defaults to ROM start.",
)
@click.option(
    "--end",
    "end_addr",
    help="End address (hex, exclusive). Defaults to ROM end.",
)
@click.option(
    "--label-hint",
    "extra_label_hints",
    multiple=True,
    help=(
        'Add a label hint, format "PATTERN=description" (e.g. '
        '--label-hint "wksp_drive=current drive"). Merges with hints '
        "from fantasm.toml. Repeatable."
    ),
)
@report_output(reports={"suggestions": "Comment suggestions"})
def comments_suggest(
    version_id: str,
    start_addr: str | None,
    end_addr: str | None,
    extra_label_hints: tuple[str, ...],
) -> Reports:
    actx = analysis_context(click.get_current_context(), version_id)
    data = actx.data

    suggest_section = (
        actx.project.config.get("comments", {})
        .get("suggest", {})
        .get("label_hints", {})
    )
    label_hints: dict[str, str] = dict(suggest_section)

    for entry in extra_label_hints:
        if "=" not in entry:
            raise click.UsageError(
                f"--label-hint must be PATTERN=description, got: {entry!r}"
            )
        pattern, _, description = entry.partition("=")
        label_hints[pattern.strip()] = description.strip()

    def _parse_hex(text: str) -> int:
        result = parse_address(text)
        if result is None:
            raise click.UsageError(f"invalid address {text!r}")
        return result

    address_range: tuple[int, int] | None = None
    if start_addr or end_addr:
        meta = data.get("meta", {})
        rom_start = meta.get("load_addr", 0x8000)
        rom_end = meta.get("end_addr", rom_start + 0x2000)
        start = _parse_hex(start_addr) if start_addr else rom_start
        end = _parse_hex(end_addr) if end_addr else rom_end
        address_range = (start, end)

    declared_subs = {
        sub["addr"] for sub in data.get("subroutines", [])
    }

    suggestions = suggest_comments(
        data["items"],
        label_hints=label_hints,
        declared_subs=declared_subs,
        address_range=address_range,
    )

    description_parts = [f"{len(suggestions)} suggestions"]
    if label_hints:
        description_parts.append(f"{len(label_hints)} label hints active")
    if address_range:
        description_parts.append(
            f"range &{address_range[0]:04X}-&{address_range[1]:04X}"
        )

    table = (
        TableContent(
            title=f"Comment suggestions for {version_id}",
            description="; ".join(description_parts),
        )
        .add_column("addr", "Addr")
        .add_column("text", "Suggestion")
        .add_column("py_line", "Driver line")
    )
    for suggestion in suggestions:
        py_line = (
            f'comment(0x{suggestion.addr:04X}, '
            f'"{suggestion.text}", inline=True)'
        )
        table.add_row(
            addr=f"&{suggestion.addr:04X}",
            text=suggestion.text,
            py_line=py_line,
        )
    return Reports(suggestions=Report(data=table))


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
    actx = analysis_context(click.get_current_context(), version_id)
    try:
        findings = run_checks(
            actx.data, sub_target=sub_target, regions=actx.base_regions
        )
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
