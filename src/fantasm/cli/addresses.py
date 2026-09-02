"""``fantasm addresses`` — address translation across ROM versions."""

from __future__ import annotations

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from ..api.blockmatch import build_full_address_map
from ..cli_helpers import (
    project_cpu,
    project_binary_base,
    require_project,
    resolve_version_files,
)
from ._options import cpu_option, rom_base_option


@click.group(help="Address translation across ROM versions.")
def addresses() -> None:
    pass


@addresses.command(
    "map",
    help=(
        "Map addresses from SOURCE_VERSION to TARGET_VERSION via "
        "opcode-level matching. With no --addr arguments, emits the "
        "full mapping (large for real ROMs — pipe through --as tsv). "
        "With --addr, only the specified source addresses are mapped."
    ),
)
@click.argument("source_version")
@click.argument("target_version")
@click.option(
    "--addr",
    "addrs",
    multiple=True,
    help="Source address to map (hex, with or without 0x/$/&). Repeatable.",
)
@click.option(
    "--threshold",
    type=click.IntRange(1, 1000),
    default=5,
    show_default=True,
    help=(
        "Minimum anchored shared-block length (in opcodes) for a "
        "mapping to be emitted. Defaults to 5 to match "
        "``fantasm backfill``; lower deliberately when working with "
        "tiny ROMs or fixtures."
    ),
)
@cpu_option
@rom_base_option
@click.option(
    "--include-supplementary/--primary-only",
    default=True,
    show_default=True,
    help=(
        "Include the seed-and-extend supplementary mappings (catches "
        "reordered blocks the LCS misses). --primary-only restricts "
        "to the LCS-derived mappings only."
    ),
)
@report_output(reports={"map": "Source→target address mapping"})
def addresses_map(
    source_version: str,
    target_version: str,
    addrs: tuple[str, ...],
    threshold: int,
    cpu: str | None,
    rom_base: int | None,
    include_supplementary: bool,
) -> Reports:
    ctx = click.get_current_context()
    project_context = require_project(ctx)
    if cpu is None:
        cpu = project_cpu(project_context)
    if rom_base is None:
        rom_base = project_binary_base(project_context)

    files_source = resolve_version_files(project_context, source_version)
    files_target = resolve_version_files(project_context, target_version)
    if not files_source.binary_filepath.exists():
        raise click.UsageError(f"binary not found: {files_source.binary_filepath}")
    if not files_target.binary_filepath.exists():
        raise click.UsageError(f"binary not found: {files_target.binary_filepath}")

    rom_source = files_source.binary_filepath.read_bytes()
    rom_target = files_target.binary_filepath.read_bytes()

    full_map, primary_map, supplementary_map, _blocks = build_full_address_map(
        rom_source, rom_target,
        cpu_a=cpu, cpu_b=cpu,
        rom_base=rom_base,
        min_block_length=threshold,
    )

    if include_supplementary:
        addr_map = full_map
    else:
        addr_map = primary_map

    if addrs:
        wanted: list[int] = []
        for raw in addrs:
            cleaned = raw.strip().lstrip("$&").removeprefix("0x")
            try:
                wanted.append(int(cleaned, 16))
            except ValueError as exc:
                raise click.UsageError(
                    f"invalid address {raw!r}"
                ) from exc
        rows = [(a, addr_map.get(a)) for a in wanted]
    else:
        rows = sorted(addr_map.items())

    table = (
        TableContent(
            title=f"{source_version} → {target_version}",
            description=(
                f"primary {len(primary_map)} + supplementary "
                f"{len(supplementary_map)} entries; "
                f"showing {len(rows)} row(s)"
                + ("" if include_supplementary else " (primary only)")
            ),
        )
        .add_column("source", "Source")
        .add_column("target", "Target")
        .add_column("source_method", "Via")
    )
    for source_addr, target in rows:
        if isinstance(target, tuple):
            target_addr = target[0]
        else:
            target_addr = target
        if target_addr is None:
            table.add_row(
                source=f"&{source_addr:04X}",
                target="-",
                source_method="(no mapping)",
            )
            continue
        method = "primary" if source_addr in primary_map else "supplementary"
        table.add_row(
            source=f"&{source_addr:04X}",
            target=f"&{target_addr:04X}",
            source_method=method,
        )
    return Reports(map=Report(data=table))
