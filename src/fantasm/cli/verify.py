"""``fantasm verify`` — round-trip a disassembly through its assembler."""

from __future__ import annotations

import click

from ..api.paths import project_versions_dirpath
from ..api.targets import (
    TargetConfigError,
    list_target_ids,
    target_verify_settings,
    uses_target_config,
)
from ..api.verify import (
    AssemblerConfig,
    AssemblerConfigError,
    AssemblerNotFoundError,
    AssemblerOutputMissingError,
    VerifyResult,
    verify_round_trip,
)
from ..cli_helpers import require_project, resolve_version_files
from ..config import ProjectContext
from ._target import TargetCommand


class VerifyCommand(TargetCommand):
    """``verify`` names no target when ``--all`` is given."""

    suppress_default_target_for = frozenset({"verify_all"})
    missing_target_hint = " (or pass --all)"


def _assembler_for(
    project_context: ProjectContext, target_id: str
) -> AssemblerConfig:
    try:
        return AssemblerConfig.from_mapping(
            target_verify_settings(project_context, target_id)
        )
    except (AssemblerConfigError, TargetConfigError) as exc:
        raise click.UsageError(str(exc)) from exc


def _run(
    project_context: ProjectContext, target_id: str
) -> tuple[VerifyResult, AssemblerConfig]:
    files = resolve_version_files(project_context, target_id)
    assembler = _assembler_for(project_context, target_id)
    result = verify_round_trip(
        files.binary_filepath,
        files.asm_filepath,
        assembler=assembler,
        project_root_dirpath=project_context.root_dirpath,
    )
    return result, assembler


def _error_detail(result: VerifyResult, assembler: AssemblerConfig) -> str:
    if result.first_diff_offset is not None:
        return f"first_diff=&{result.first_diff_offset:04X}"
    return f"({assembler.display_name} error)"


@click.command(
    cls=VerifyCommand,
    help=(
        "Verify a disassembly round-trips: assemble its .asm and "
        "compare the bytes to the original binary. The assembler is "
        "beebasm unless fantasm.toml's [verify] section configures "
        "another. TARGET may be omitted when the project has a single "
        "target or a [project] default_target. Pass --all to verify "
        "every target in the project."
    ),
)
@click.argument("version_id", metavar="[TARGET]", required=False)
@click.option(
    "--all",
    "verify_all",
    is_flag=True,
    help="Verify every target in the project.",
)
@click.pass_context
def verify(
    ctx: click.Context, version_id: str | None, verify_all: bool
) -> None:
    project_context = require_project(ctx)

    if verify_all and version_id is not None:
        raise click.UsageError(
            "pass either TARGET or --all, not both"
        )
    if not verify_all and version_id is None:
        raise click.UsageError("provide TARGET or --all")

    if verify_all:
        try:
            target_ids = list_target_ids(project_context)
        except TargetConfigError as exc:
            raise click.UsageError(str(exc)) from exc
        if not target_ids:
            if uses_target_config(project_context):
                raise click.UsageError("no targets found in the project")
            raise click.UsageError(
                "no versions found under "
                f"{project_versions_dirpath(project_context)}"
            )

        passes = 0
        failures = 0
        for target_id in target_ids:
            files = resolve_version_files(project_context, target_id)
            if not files.binary_filepath.exists() or not files.asm_filepath.exists():
                click.echo(
                    f"{target_id}: SKIPPED (missing binary or asm)",
                    err=True,
                )
                failures += 1
                continue
            try:
                result, assembler = _run(project_context, target_id)
            except AssemblerNotFoundError as exc:
                raise click.UsageError(str(exc)) from exc
            except AssemblerOutputMissingError as exc:
                click.echo(f"{target_id}: FAILED ({exc})", err=True)
                failures += 1
                continue
            if result.matched:
                slice_note = (
                    f" sliced from {result.rom_size}b"
                    if result.compared_size != result.rom_size
                    else ""
                )
                click.echo(
                    f"{target_id}: PASSED ({result.compared_size} bytes{slice_note})"
                )
                passes += 1
            else:
                slice_note = (
                    f" compared={result.compared_size}b"
                    if result.compared_size != result.rom_size
                    else ""
                )
                click.echo(
                    f"{target_id}: FAILED binary={result.rom_size}b{slice_note} "
                    f"assembled={result.assembled_size}b "
                    f"{_error_detail(result, assembler)}",
                    err=True,
                )
                failures += 1
        click.echo(f"\n{passes} passed, {failures} failed")
        if failures:
            ctx.exit(1)
        return

    try:
        result, assembler = _run(project_context, version_id)
    except FileNotFoundError as exc:
        raise click.UsageError(str(exc)) from exc
    except (AssemblerNotFoundError, AssemblerOutputMissingError) as exc:
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
        + _error_detail(result, assembler),
        err=True,
    )
    if result.beebasm_returncode != 0 and result.beebasm_stderr:
        click.echo(result.beebasm_stderr, err=True)
    ctx.exit(1)
