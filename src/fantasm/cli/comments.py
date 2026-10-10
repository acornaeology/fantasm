"""``fantasm comments`` — comment / annotation consistency checks."""

from __future__ import annotations

import json
import sys

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from ..api.asm_extract import parse_address
from ..api.comment_check import ParentVersion, run_checks
from ..api.driver_annotations import (
    DriverAnnotation,
    DriverParseError,
    parse_driver_annotations,
)
from ..api.suggest import suggest_comments
from ..api.version_graph import (
    VersionGraphError,
    compose_chained_map,
    load_version_graph,
)
from ..cli_helpers import (
    AnalysisContext,
    analysis_context,
    make_binary_loader,
    project_binary_base,
    project_cpu,
    resolve_version_files,
)


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
        "version's JSON output. When the version's driver script is "
        "present, also flags inline comments keyed to an address "
        "inside an instruction or data item. When the version has "
        "parents in the version graph, also flags comments copied "
        "from a parent at the same numeric address onto a different "
        "instruction."
    ),
)
@click.argument("version_id")
@click.option(
    "--sub",
    "sub_target",
    help="Restrict to the subroutine starting at this hex address.",
)
@click.option(
    "--strict",
    is_flag=True,
    default=False,
    help=(
        "Exit non-zero if any HIGH-confidence finding is reported. "
        "Use as a CI gate: HIGH findings (wrong register / wrong "
        "branch target / wrong CR / wrong tube register / Markdown "
        "link inside a backtick code span / lo-hi byte of the wrong "
        "address / inline comment inside an instruction) almost "
        "certainly disagree with the code."
    ),
)
@click.option(
    "--parents/--no-parents",
    "check_parents",
    default=True,
    help=(
        "Compare against the version's parents in the version graph "
        "(default on). --no-parents skips the comparison, which also "
        "skips building the parent-to-child address map."
    ),
)
@report_output(reports={"findings": "Comment-check findings"})
def comments_check(
    version_id: str, sub_target: str | None, strict: bool, check_parents: bool
) -> Reports:
    ctx = click.get_current_context()
    actx = analysis_context(ctx, version_id)
    driver_annotations = _load_driver_annotations(actx)
    parents = _load_parents(actx) if check_parents else []
    try:
        findings = run_checks(
            actx.data,
            sub_target=sub_target,
            regions=actx.base_regions,
            driver_annotations=driver_annotations,
            parents=parents,
        )
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc

    high = sum(1 for f in findings if f["confidence"] == "HIGH")
    medium = sum(1 for f in findings if f["confidence"] == "MEDIUM")

    if strict and high:
        # Render first, then exit non-zero. ``call_on_close`` fires
        # after asyoulikeit has flushed its output.
        ctx.call_on_close(lambda: sys.exit(1))

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


def _load_driver_annotations(
    actx: AnalysisContext,
) -> list[DriverAnnotation] | None:
    """The version's driver annotations, or ``None`` if it has no driver."""
    driver_filepath = actx.files.driver_filepath
    if not driver_filepath.exists():
        return None
    try:
        return parse_driver_annotations(driver_filepath.read_text())
    except DriverParseError as exc:
        raise click.UsageError(f"{driver_filepath}: {exc}") from exc


def _load_parents(actx: AnalysisContext) -> list[ParentVersion]:
    """Each graph parent of the version whose JSON output exists.

    The parent-to-child address map is attached when both binaries
    load; without it the copied-comment check still runs, just
    without saying where the parent's instruction moved to.
    """
    project_context = actx.project
    try:
        graph = load_version_graph(project_context)
    except VersionGraphError:
        return []
    if actx.version_id not in graph:
        return []

    loader = make_binary_loader(project_context)
    parents: list[ParentVersion] = []
    for parent_id in graph.get(actx.version_id).parents:
        json_filepath = resolve_version_files(
            project_context, parent_id
        ).json_filepath
        if not json_filepath.exists():
            continue
        try:
            address_map = compose_chained_map(
                graph,
                parent_id,
                actx.version_id,
                loader,
                rom_base=project_binary_base(project_context),
                cpu=project_cpu(project_context),
            )
        except (VersionGraphError, FileNotFoundError, click.UsageError):
            address_map = None
        parents.append(
            ParentVersion(
                version_id=parent_id,
                data=json.loads(json_filepath.read_text()),
                address_map=address_map,
            )
        )
    return parents
