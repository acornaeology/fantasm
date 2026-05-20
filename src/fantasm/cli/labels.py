"""``fantasm labels`` — auto-label classification and renaming."""

from __future__ import annotations

import difflib
import re
import tomllib
from pathlib import Path

import click
from asyoulikeit import (
    Report,
    Reports,
    TableContent,
    TreeContent,
    report_output,
)

from ..api.labels import (
    build_target_refs,
    classify_labels,
    collect_auto_labels,
    inbound_refs_to,
    label_inventory,
    sort_labels,
)
from ..api.rename_labels import (
    apply_renames_inline,
    apply_renames_to_lines,
    update_ref_strings,
)
from ..cli_helpers import analysis_context
from ._options import (
    label_match_option,
    label_max_length_option,
    label_min_length_option,
    label_reverse_option,
    label_sort_option,
    label_source_option,
)


_LABEL_SORT_KEYS: dict[str, callable] = {
    "name": lambda r: (r["name"], r["addr"]),
    "addr": lambda r: (r["addr"], r["name"]),
    "len": lambda r: (r["length"], r["name"]),
    "refs": lambda r: (r["ref_count"], r["name"]),
}


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
        "tables, each with `addr` (integer) and `name` (string).\n"
        "\n"
        "Default (inline) mode rewrites each scattered `label(0xXXXX, …)` "
        "or `d.label(0xXXXX, …)` declaration in place wherever it sits in "
        "the driver, and errors if any requested address has no matching "
        "declaration. Pass --section for the legacy override-cluster "
        "behaviour that operates only on a `# Code label renames` block.\n"
        "\n"
        "Pass --update-refs to also rewrite textual references to the old "
        "name in `d.comment(\"…\")` arguments, `description=\"\"\"…\"\"\"` "
        "blocks, and Markdown `[`name`](address:…)` anchors. Other "
        "occurrences are left alone.\n"
        "\n"
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
    "--section",
    is_flag=True,
    help=(
        "Use the legacy section-based rewrite that targets a "
        "`# Code label renames` block. Default is inline rewrite of "
        "scattered declarations."
    ),
)
@click.option(
    "--update-refs",
    is_flag=True,
    help=(
        "Also rewrite textual references to the renamed labels in "
        "d.comment(\"…\") args, description=\"\"\"…\"\"\" blocks, and "
        "Markdown [`name`](address:…) anchors. Inline mode only."
    ),
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
    section: bool,
    update_refs: bool,
    in_place: bool,
    output_filepath: Path | None,
    dry_run: bool,
) -> None:
    if sum([in_place, output_filepath is not None, dry_run]) > 1:
        raise click.UsageError(
            "pass at most one of --in-place, --output, --dry-run"
        )
    if update_refs and section:
        raise click.UsageError(
            "--update-refs is only meaningful in inline mode (drop --section)"
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
    ref_count = 0
    try:
        if section:
            new_lines = apply_renames_to_lines(lines, rename_map)
        else:
            new_lines, name_map = apply_renames_inline(lines, rename_map)
            if update_refs:
                new_lines, ref_count = update_ref_strings(
                    new_lines, name_map
                )
    except LookupError as exc:
        raise click.UsageError(str(exc)) from exc

    new_text = "".join(new_lines)

    summary = f"{len(rename_map)} rename(s)"
    if update_refs:
        summary += f" + {ref_count} textual reference(s)"

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
        click.echo(f"Wrote {summary} to {driver_filepath}")
        return
    if output_filepath is not None:
        output_filepath.write_text(new_text)
        click.echo(f"Wrote {summary} to {output_filepath}")
        return
    click.echo(new_text, nl=False)


@labels.command(
    "list",
    help=(
        "Inventory every label declared in a version's disassembly. "
        "By default shows name, address, source (driver vs env), "
        "length, and inbound reference count. Filter with --match / "
        "--min-length / --max-length / --source; sort with --sort / "
        "--reverse."
    ),
)
@click.argument("version_id")
@label_sort_option
@label_reverse_option
@label_min_length_option
@label_max_length_option
@label_match_option
@label_source_option
@report_output(reports={"labels": "Label inventory"})
def labels_list(
    version_id: str,
    sort_key: str,
    reverse: bool,
    min_length: int | None,
    max_length: int | None,
    match_pattern: str | None,
    source: str,
) -> Reports:
    actx = analysis_context(click.get_current_context(), version_id)
    inventory = label_inventory(actx.data)

    try:
        pattern = re.compile(match_pattern) if match_pattern else None
    except re.error as exc:
        raise click.UsageError(
            f"invalid --match regular expression: {exc}"
        ) from exc

    source_lc = source.lower()
    if source_lc != "all":
        inventory = [r for r in inventory if r["source"] == source_lc]
    if min_length is not None:
        inventory = [r for r in inventory if r["length"] >= min_length]
    if max_length is not None:
        inventory = [r for r in inventory if r["length"] <= max_length]
    if pattern is not None:
        inventory = [r for r in inventory if pattern.search(r["name"])]

    inventory.sort(key=_LABEL_SORT_KEYS[sort_key.lower()], reverse=reverse)

    description_parts = [f"{len(inventory)} label(s)"]
    if source_lc != "all":
        description_parts.append(f"source={source_lc}")
    if min_length is not None:
        description_parts.append(f"min-length={min_length}")
    if max_length is not None:
        description_parts.append(f"max-length={max_length}")
    if match_pattern is not None:
        description_parts.append(f"match={match_pattern!r}")

    table = (
        TableContent(
            title=f"Labels in {version_id}",
            description=", ".join(description_parts),
        )
        .add_column("name", "Name")
        .add_column("addr", "Addr")
        .add_column("source", "Source")
        .add_column("length", "Len")
        .add_column("refs", "Refs")
    )
    for record in inventory:
        table.add_row(
            name=record["name"],
            addr=f"&{record['addr']:04X}",
            source=record["source"],
            length=str(record["length"]),
            refs=str(record["ref_count"]),
        )
    return Reports(labels=Report(data=table))


@labels.command(
    "refs",
    help=(
        "Show the inbound reference sites for a single label, "
        "as a tree rooted at the label. Combines code-flow refs "
        "(items whose target is the label's address) and data "
        "refs (table / pointer references). Exits with an error "
        "if the label is not declared in the version."
    ),
)
@click.argument("version_id")
@click.argument("label_name")
@report_output(reports={"refs": "Label reference sites"})
def labels_refs(version_id: str, label_name: str) -> Reports:
    actx = analysis_context(click.get_current_context(), version_id)
    data = actx.data
    items = data.get("items", [])
    items_by_addr = {item["addr"]: item for item in items}
    target_refs = build_target_refs(items)

    addrs: list[int] = []
    for item in items:
        if label_name in item.get("labels", []):
            addrs.append(item["addr"])
        for addr_str, sub_labels in item.get("sub_labels", {}).items():
            if label_name in sub_labels:
                addrs.append(int(addr_str))
    external_addr = data.get("external_labels", {}).get(label_name)
    source = "driver" if addrs else None
    if external_addr is not None and not addrs:
        addrs.append(int(external_addr))
        source = "env"

    if not addrs:
        raise click.UsageError(
            f"label {label_name!r} not found in {version_id}"
        )

    deduped: list[int] = []
    for addr in addrs:
        if addr not in deduped:
            deduped.append(addr)

    refs_by_addr = {
        addr: inbound_refs_to(addr, items_by_addr, target_refs)
        for addr in deduped
    }
    total = sum(len(refs) for refs in refs_by_addr.values())

    tree = (
        TreeContent(
            title=f"References to {label_name} in {version_id}",
            description=(
                f"{total} inbound reference(s) across "
                f"{len(deduped)} declaration(s)"
            ),
        )
        .add_column("site", "Site", header=True)
        .add_column("addr", "Addr")
        .add_column("mnemonic", "Op")
    )
    label_node = tree.add_root(
        site=f"{label_name} ({source})",
        addr=f"&{deduped[0]:04X}" if len(deduped) == 1 else "",
        mnemonic="",
    )
    for decl_addr in deduped:
        decl_refs = refs_by_addr[decl_addr]
        if len(deduped) == 1:
            decl_node = label_node
        else:
            decl_node = label_node.add_child(
                site=f"@{decl_addr:04X}",
                addr=f"&{decl_addr:04X}",
                mnemonic="",
            )
        for ref in decl_refs:
            decl_node.add_child(
                site=ref["mnemonic"],
                addr=f"&{ref['addr']:04X}",
                mnemonic=ref["mnemonic"],
            )
    return Reports(refs=Report(data=tree))
