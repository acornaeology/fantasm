"""``fantasm compare`` — diff two ROM versions."""

from __future__ import annotations

import click

from ..api.compare import compare_roms
from ..cli_helpers import (
    project_cpu,
    project_binary_base,
    require_project,
    resolve_version_files,
)
from ._options import cpu_option, rom_base_option


@click.command(
    help=(
        "Compare two ROM versions at byte / opcode / full-instruction "
        "granularity and print a diff report."
    ),
)
@click.argument("version_a")
@click.argument("version_b")
@cpu_option
@rom_base_option
@click.pass_context
def compare(
    ctx: click.Context,
    version_a: str,
    version_b: str,
    cpu: str | None,
    rom_base: int | None,
) -> None:
    project_context = require_project(ctx)
    if cpu is None:
        cpu = project_cpu(project_context)
    if rom_base is None:
        rom_base = project_binary_base(project_context)
    files_a = resolve_version_files(project_context, version_a)
    files_b = resolve_version_files(project_context, version_b)

    if not files_a.binary_filepath.exists():
        raise click.UsageError(
            f"binary not found: {files_a.binary_filepath}"
        )
    if not files_b.binary_filepath.exists():
        raise click.UsageError(
            f"binary not found: {files_b.binary_filepath}"
        )

    data_a = files_a.binary_filepath.read_bytes()
    data_b = files_b.binary_filepath.read_bytes()
    report = compare_roms(
        data_a, data_b, version_a, version_b,
        cpu_a=cpu, cpu_b=cpu, rom_base=rom_base,
    )
    click.echo(report)
