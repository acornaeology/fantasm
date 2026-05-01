"""``fantasm shared`` — find shared 6502 code fragments across ROMs."""

from __future__ import annotations

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from ..api.find_shared import (
    find_matching_spans,
    load_rom,
    parse_rom_spec,
)


@click.command(
    "shared",
    help=(
        "Find shared 6502 code fragments between a primary ROM and "
        "one or more reference ROMs. Specs use the form "
        "[label=]path@load-addr (e.g. nfs=path/to/nfs.rom@&8000)."
    ),
)
@click.argument("primary")
@click.argument("references", nargs=-1, required=True)
@click.option(
    "--min-len",
    type=click.IntRange(1, 1000),
    default=8,
    show_default=True,
    help="Minimum matching span length, in instructions.",
)
@click.option(
    "--limit",
    type=click.IntRange(1, 1000),
    default=None,
    help="Show at most N longest matches per reference.",
)
@report_output(reports={"matches": "Shared code spans"})
def shared(
    primary: str,
    references: tuple[str, ...],
    min_len: int,
    limit: int | None,
) -> Reports:
    try:
        p_label, p_path, p_base = parse_rom_spec(primary)
    except (ValueError, FileNotFoundError) as exc:
        raise click.UsageError(str(exc)) from exc

    primary_rom = load_rom(p_label, p_path, p_base)

    table = (
        TableContent(
            title=f"Shared spans against {primary_rom.label}",
            description=(
                f"{len(primary_rom.data)} bytes @ &{primary_rom.load_addr:04X}"
            ),
        )
        .add_column("reference", "Reference")
        .add_column("size", "Instr")
        .add_column("bytes", "Bytes")
        .add_column("primary", "Primary addr")
        .add_column("ref", "Reference addr")
    )

    for spec in references:
        try:
            r_label, r_path, r_base = parse_rom_spec(spec)
        except (ValueError, FileNotFoundError) as exc:
            raise click.UsageError(str(exc)) from exc
        reference = load_rom(r_label, r_path, r_base)
        matches = find_matching_spans(primary_rom, reference, min_len)
        matches.sort(key=lambda m: -m[2])
        if limit is not None:
            matches = matches[:limit]
        for a_idx, b_idx, size in matches:
            a_addr = primary_rom.runtime_addr(a_idx)
            b_addr = reference.runtime_addr(b_idx)
            a_off = primary_rom.instructions[a_idx].offset
            a_end_idx = a_idx + size
            a_end_off = (
                primary_rom.instructions[a_end_idx].offset
                if a_end_idx < len(primary_rom.instructions)
                else len(primary_rom.data)
            )
            span_bytes = a_end_off - a_off
            table.add_row(
                reference=r_label,
                size=str(size),
                bytes=str(span_bytes),
                primary=f"&{a_addr:04X}",
                ref=f"&{b_addr:04X}",
            )

    return Reports(matches=Report(data=table))
