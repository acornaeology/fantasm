"""``fantasm fingerprint`` — block-level fingerprinting for duplicate detection."""

from __future__ import annotations

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from ..api.fingerprint import find_duplicate_blocks, fingerprint_blocks
from ..cli_helpers import analysis_context, project_cpu, project_rom_base
from ._options import cpu_option, rom_base_option


@click.command(
    "fingerprint",
    help=(
        "Fingerprint each block of a ROM version's bytes and report any "
        "duplicate blocks (a quick cross-check for relocated code)."
    ),
)
@click.argument("version_id")
@click.option(
    "--block-size",
    type=click.IntRange(1, 4096),
    default=64,
    show_default=True,
    help="Block size in bytes.",
)
@cpu_option
@rom_base_option
@report_output(reports={"duplicates": "Duplicate blocks"})
def fingerprint_cmd(
    version_id: str,
    block_size: int,
    cpu: str | None,
    rom_base: int | None,
) -> Reports:
    actx = analysis_context(click.get_current_context(), version_id)
    if cpu is None:
        cpu = project_cpu(actx.project)
    if rom_base is None:
        rom_base = project_rom_base(actx.project)
    if not actx.files.rom_filepath.exists():
        raise click.UsageError(f"ROM not found: {actx.files.rom_filepath}")

    fps = fingerprint_blocks(
        actx.files.rom_filepath.read_bytes(),
        block_size=block_size,
        cpu=cpu,
        rom_base=rom_base,
    )
    duplicates = find_duplicate_blocks(fps)

    table = (
        TableContent(
            title=f"Duplicate blocks in {version_id}",
            description=(
                f"{len(duplicates)} duplicate fingerprints "
                f"out of {len(fps)} blocks"
            ),
        )
        .add_column("fingerprint", "Fingerprint")
        .add_column("count", "Count")
        .add_column("addresses", "Addresses")
    )
    for fp, addrs in sorted(duplicates.items(), key=lambda x: -len(x[1])):
        table.add_row(
            fingerprint=fp,
            count=str(len(addrs)),
            addresses=", ".join(f"&{a:04X}" for a in addrs),
        )
    return Reports(duplicates=Report(data=table))
