"""``fantasm verify`` — round-trip a disassembly through beebasm."""

from __future__ import annotations

import click

from ..api.paths import project_rom_prefixes, project_versions_dirpath
from ..api.project import list_versions
from ..api.verify import BeebasmNotFoundError, verify_round_trip
from ..cli_helpers import require_project, resolve_version_files


@click.command(
    help=(
        "Verify a disassembly round-trips: assemble its .asm with "
        "beebasm and compare bytes to the original ROM. Pass --all "
        "to verify every version registered in the project's "
        "versions/ directory."
    ),
)
@click.argument("version_id", required=False)
@click.option(
    "--all",
    "verify_all",
    is_flag=True,
    help="Verify every version under the project's versions/ directory.",
)
@click.pass_context
def verify(
    ctx: click.Context, version_id: str | None, verify_all: bool
) -> None:
    project_context = require_project(ctx)

    if verify_all and version_id is not None:
        raise click.UsageError(
            "pass either VERSION_ID or --all, not both"
        )
    if not verify_all and version_id is None:
        raise click.UsageError("provide VERSION_ID or --all")

    if verify_all:
        versions_dirpath = project_versions_dirpath(project_context)
        prefixes = project_rom_prefixes(project_context)
        if not prefixes:
            raise click.UsageError(
                "no [versions] prefixes configured in fantasm.toml"
            )
        infos = list_versions(versions_dirpath, prefixes)
        if not infos:
            raise click.UsageError(
                f"no versions found under {versions_dirpath}"
            )

        passes = 0
        failures = 0
        for info in infos:
            files = resolve_version_files(project_context, info.version_id)
            if not files.binary_filepath.exists() or not files.asm_filepath.exists():
                click.echo(
                    f"{info.version_id}: SKIPPED (missing binary or asm)",
                    err=True,
                )
                failures += 1
                continue
            try:
                result = verify_round_trip(
                    files.binary_filepath, files.asm_filepath
                )
            except BeebasmNotFoundError as exc:
                raise click.UsageError(str(exc)) from exc
            if result.matched:
                slice_note = (
                    f" sliced from {result.rom_size}b"
                    if result.compared_size != result.rom_size
                    else ""
                )
                click.echo(
                    f"{info.version_id}: PASSED ({result.compared_size} bytes{slice_note})"
                )
                passes += 1
            else:
                if result.first_diff_offset is not None:
                    detail = f"first_diff=&{result.first_diff_offset:04X}"
                else:
                    detail = "(beebasm error)"
                slice_note = (
                    f" compared={result.compared_size}b"
                    if result.compared_size != result.rom_size
                    else ""
                )
                click.echo(
                    f"{info.version_id}: FAILED binary={result.rom_size}b{slice_note} "
                    f"assembled={result.assembled_size}b {detail}",
                    err=True,
                )
                failures += 1
        click.echo(f"\n{passes} passed, {failures} failed")
        if failures:
            ctx.exit(1)
        return

    files = resolve_version_files(project_context, version_id)
    try:
        result = verify_round_trip(files.binary_filepath, files.asm_filepath)
    except FileNotFoundError as exc:
        raise click.UsageError(str(exc)) from exc
    except BeebasmNotFoundError as exc:
        raise click.UsageError(str(exc)) from exc

    if result.matched:
        slice_note = (
            f" (sliced from {result.rom_size}-byte binary)"
            if result.compared_size != result.rom_size
            else ""
        )
        click.echo(
            f"Verification PASSED: {result.compared_size} bytes match{slice_note}"
        )
        return
    slice_note = (
        f" compared={result.compared_size}b"
        if result.compared_size != result.rom_size
        else ""
    )
    click.echo(
        f"Verification FAILED: binary={result.rom_size}b{slice_note} "
        f"assembled={result.assembled_size}b "
        + (
            f"first_diff=&{result.first_diff_offset:04X}"
            if result.first_diff_offset is not None
            else "(beebasm error)"
        ),
        err=True,
    )
    if result.beebasm_returncode != 0 and result.beebasm_stderr:
        click.echo(result.beebasm_stderr, err=True)
    ctx.exit(1)
