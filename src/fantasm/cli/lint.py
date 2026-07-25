"""``fantasm lint`` — validate driver-script annotation addresses."""

from __future__ import annotations

import json
from pathlib import Path

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from ..api.lint import (
    address_in_ranges,
    extract_annotations,
    find_inline_scheme_links,
    glossary_slugs_from_markdown,
    valid_addresses_from_data,
    valid_label_names_from_data,
)
from ..cli_helpers import analysis_context


def _collect_broken_scheme_links(actx, driver_filepath):
    """Find inline ``label:`` / ``glossary:`` links in the driver and the
    version's doc Markdown whose target doesn't resolve.

    ``label:NAME`` is checked against the version's label set; a
    ``glossary:SLUG`` is checked against ``GLOSSARY.md`` at the project
    root (skipped if that file can't be located, since the glossary is
    a project-level, not per-version, artifact).
    """
    valid_labels = valid_label_names_from_data(actx.data)

    glossary_slugs = None
    root_dirpath = getattr(actx.project, "root_dirpath", None)
    if root_dirpath is not None:
        glossary_filepath = Path(root_dirpath) / "GLOSSARY.md"
        if glossary_filepath.is_file():
            glossary_slugs = glossary_slugs_from_markdown(
                glossary_filepath.read_text())

    sources = [(driver_filepath.name, driver_filepath.read_text())]
    rom_json_filepath = actx.files.version_dirpath / "rom" / "rom.json"
    if rom_json_filepath.is_file():
        rom_meta = json.loads(rom_json_filepath.read_text())
        for doc in rom_meta.get("docs", []):
            doc_filepath = actx.files.version_dirpath / doc["path"]
            if doc_filepath.is_file():
                sources.append((doc["path"], doc_filepath.read_text()))

    broken = []
    for source_label, text in sources:
        for link in find_inline_scheme_links(text):
            if link["scheme"] == "label":
                if link["name"] not in valid_labels:
                    broken.append({**link, "source": source_label,
                                   "reason": "unknown label"})
            elif glossary_slugs is not None:
                if link["name"] not in glossary_slugs:
                    broken.append({**link, "source": source_label,
                                   "reason": "unknown glossary slug"})
    return broken


@click.command(
    "lint",
    help=(
        "Validate that a driver script's annotation addresses "
        "(comment / subroutine / label) all map to addresses present "
        "in the version's disassembly output, the version's declared "
        "workspace regions, or its external_labels."
    ),
)
@click.argument("version_id")
@click.argument(
    "driver_filepath",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@report_output(reports={
    "unmapped": "Annotations whose addresses are not in the disassembly",
    "broken_links": "Inline label:/glossary: links whose target doesn't resolve",
})
def lint_annotations(
    version_id: str, driver_filepath: Path
) -> Reports:
    actx = analysis_context(click.get_current_context(), version_id)
    # Per-address valid set: items, sub_labels, external_labels,
    # subroutines, and the full ROM range. The set covers anything
    # the disassembler emitted into the JSON (dasmos and py8dis
    # share the same JSON shape). Workspace regions outside that
    # set still come from the version graph (effective_regions).
    valid_addresses = valid_addresses_from_data(actx.data)
    annotations = extract_annotations(driver_filepath.read_text())

    unmapped = [
        a for a in annotations
        if a.get("detail") != "metadata_only"
        and a["address"] not in valid_addresses
        and not address_in_ranges(a["address"], actx.base_regions)
    ]

    table = (
        TableContent(
            title=f"Lint findings for {version_id}",
            description=(
                f"{len(unmapped)} unmapped annotations "
                f"of {len(annotations)} total"
            ),
        )
        .add_column("addr", "Addr")
        .add_column("kind", "Kind")
        .add_column("name", "Name")
        .add_column("line", "Line")
    )
    for ann in sorted(unmapped, key=lambda a: (a["address"], a["line_number"])):
        table.add_row(
            addr=f"&{ann['address']:04X}",
            kind=ann["kind"],
            name=ann.get("name") or "",
            line=str(ann["line_number"]),
        )

    broken = _collect_broken_scheme_links(actx, driver_filepath)
    links_table = (
        TableContent(
            title=f"Broken inline links for {version_id}",
            description=f"{len(broken)} unresolved label:/glossary: links",
        )
        .add_column("source", "Source")
        .add_column("line", "Line")
        .add_column("scheme", "Scheme")
        .add_column("target", "Target")
        .add_column("reason", "Reason")
    )
    for link in sorted(broken, key=lambda b: (b["source"], b["line_number"])):
        links_table.add_row(
            source=link["source"],
            line=str(link["line_number"]),
            scheme=link["scheme"],
            target=link["target"],
            reason=link["reason"],
        )

    return Reports(
        unmapped=Report(data=table),
        broken_links=Report(data=links_table),
    )
