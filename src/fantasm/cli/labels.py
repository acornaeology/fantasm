"""``fantasm labels`` — auto-label classification and renaming."""

from __future__ import annotations

import difflib
import tomllib
from pathlib import Path

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from ..api.labels import (
    build_target_refs,
    classify_labels,
    collect_auto_labels,
    sort_labels,
)
from ..api.rename_labels import apply_renames_to_lines
from ..cli_helpers import analysis_context


@click.group(help="Auto-generated label classification and renaming.")
def labels() -> None:
    pass


@labels.command(
    "classify",
    help=(
        "Classify auto-generated labels (c#### / l#### / loop_c#### / "
        "sub_c####) into categories: subroutine, shared_tail, data, "
        "internal_loop, internal_conditional."
    ),
)
@click.argument("version_id")
@click.option(
    "--category",
    type=click.Choice(
        ["subroutine", "shared_tail", "data", "internal_loop", "internal_conditional"],
        case_sensitive=False,
    ),
    help="Restrict to one category.",
)
@report_output(reports={"labels": "Auto-label classification"})
def labels_classify(version_id: str, category: str | None) -> Reports:
    actx = analysis_context(click.get_current_context(), version_id)
    items = actx.data["items"]
    target_refs = build_target_refs(items)

    classified = classify_labels(
        collect_auto_labels(items),
        items,
        target_refs,
        actx.audit_subs,
        actx.memory_regions,
    )
    classified = sort_labels(classified)
    if category:
        classified = [c for c in classified if c["category"] == category]

    table = (
        TableContent(
            title=f"Auto-labels in {version_id}",
            description=f"{len(classified)} labels"
            + (f" in category {category}" if category else ""),
        )
        .add_column("name", "Name")
        .add_column("addr", "Addr")
        .add_column("category", "Category")
        .add_column("refs", "Refs")
        .add_column("xref", "X-sub")
        .add_column("parent", "Parent")
    )
    for record in classified:
        table.add_row(
            name=record["name"],
            addr=f"&{record['addr']:04X}",
            category=record["category"],
            refs=str(len(record["inbound_refs"])),
            xref=str(record["cross_sub_count"]),
            parent=record["parent_sub_name"] or "",
        )
    return Reports(labels=Report(data=table))


@labels.command(
    "apply",
    help=(
        "Apply a renames TOML file to a disassembly driver script. "
        "The TOML file should declare a `renames` array of inline "
        "tables, each with `addr` (integer) and `name` (string). "
        "Writes the rewritten driver to stdout by default; pass "
        "--in-place or --output to write to a file."
    ),
)
@click.argument(
    "driver_filepath",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.argument(
    "renames_filepath",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--in-place",
    is_flag=True,
    help="Rewrite DRIVER_FILEPATH in place.",
)
@click.option(
    "--output",
    "output_filepath",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write the rewritten driver to OUTPUT instead of stdout.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show a unified diff of the changes without writing anything.",
)
def labels_apply(
    driver_filepath: Path,
    renames_filepath: Path,
    in_place: bool,
    output_filepath: Path | None,
    dry_run: bool,
) -> None:
    if sum([in_place, output_filepath is not None, dry_run]) > 1:
        raise click.UsageError(
            "pass at most one of --in-place, --output, --dry-run"
        )

    renames_data = tomllib.loads(renames_filepath.read_text())
    rename_entries = renames_data.get("renames")
    if not rename_entries:
        raise click.UsageError(
            f"no `renames` array found in {renames_filepath}"
        )

    rename_map: dict[int, str] = {}
    for entry in rename_entries:
        if "addr" not in entry or "name" not in entry:
            raise click.UsageError(
                f"renames entry missing addr or name: {entry}"
            )
        rename_map[int(entry["addr"])] = str(entry["name"])

    original = driver_filepath.read_text()
    lines = original.splitlines(keepends=True)
    try:
        new_lines = apply_renames_to_lines(lines, rename_map)
    except LookupError as exc:
        raise click.UsageError(str(exc)) from exc

    new_text = "".join(new_lines)

    if dry_run:
        diff = difflib.unified_diff(
            original.splitlines(keepends=True),
            new_lines,
            fromfile=str(driver_filepath),
            tofile=f"{driver_filepath} (renamed)",
        )
        click.echo("".join(diff), nl=False)
        return
    if in_place:
        driver_filepath.write_text(new_text)
        click.echo(
            f"Wrote {len(rename_map)} rename(s) to {driver_filepath}"
        )
        return
    if output_filepath is not None:
        output_filepath.write_text(new_text)
        click.echo(
            f"Wrote {len(rename_map)} rename(s) to {output_filepath}"
        )
        return
    click.echo(new_text, nl=False)
