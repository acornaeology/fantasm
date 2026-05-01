"""``fantasm sub`` — subroutine workflow helpers."""

from __future__ import annotations

from pathlib import Path

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from ..api.insert_point import AlreadyDeclared, compute_insert_point


@click.group(help="Subroutine workflow helpers.")
def sub() -> None:
    pass


@sub.command(
    "insert",
    help=(
        "Find where a new subroutine() declaration for ADDRESS belongs "
        "in the given driver script (address-sorted insertion)."
    ),
)
@click.argument(
    "driver_filepath",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.argument("address")
@report_output(reports={"insert": "Insertion point"})
def sub_insert(driver_filepath: Path, address: str) -> Reports:
    cleaned = address.strip().lstrip("$&").removeprefix("0x")
    try:
        target_addr = int(cleaned, 16)
    except ValueError as exc:
        raise click.UsageError(f"invalid address {address!r}") from exc

    lines = driver_filepath.read_text().splitlines()
    try:
        ip = compute_insert_point(lines, target_addr)
    except AlreadyDeclared as exc:
        raise click.UsageError(str(exc)) from exc
    except LookupError as exc:
        raise click.UsageError(str(exc)) from exc

    table = (
        TableContent(
            title=f"Insertion point for &{target_addr:04X}",
            description=str(driver_filepath),
        )
        .add_column("key", "Key")
        .add_column("value", "Value")
        .add_row(key="insert_line", value=str(ip.insert_line + 1))
        .add_row(
            key="predecessor",
            value=(
                f"&{ip.predecessor['addr']:04X} {ip.predecessor['name'] or ''} "
                f"(line {ip.predecessor['start_line'] + 1})"
                if ip.predecessor
                else "(start of block)"
            ),
        )
        .add_row(
            key="successor",
            value=(
                f"&{ip.successor['addr']:04X} {ip.successor['name'] or ''} "
                f"(line {ip.successor['start_line'] + 1})"
                if ip.successor
                else "(end of block)"
            ),
        )
        .add_row(
            key="block",
            value=f"lines {ip.block_start_line + 1}-{ip.block_end_line + 1}",
        )
    )
    return Reports(insert=Report(data=table))
