"""``fantasm project`` — initialise and manage fantasm projects."""

from __future__ import annotations

from pathlib import Path

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from ..api.paths import project_rom_prefixes, project_versions_dirpath
from ..api.project import (
    ProjectInitConfig,
    add_version,
    init_project,
    list_versions,
)
from ..config import ProjectContext


@click.group(help="Initialise and manage fantasm projects.")
def project() -> None:
    pass


@project.command(
    "init",
    help=(
        "Initialise a fantasm project (write fantasm.toml, create the "
        "versions directory). Safe to run inside an existing repository: "
        "no existing files are touched apart from fantasm.toml."
    ),
)
@click.option("--name", required=True, help="Project name.")
@click.option(
    "--prefix",
    "prefixes",
    multiple=True,
    help=(
        "ROM-name prefix. Repeat for multi-prefix projects (e.g. NFS's "
        "anfs/nfs). Defaults to the project name when omitted."
    ),
)
@click.option(
    "--at",
    "at_dirpath",
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    default=Path("."),
    show_default=True,
    help="Project root directory. Created if absent.",
)
@click.option(
    "--cpu",
    default="6502",
    show_default=True,
    help='Default CPU for opcode decode: "6502" / "65c02".',
)
@click.option(
    "--versions-dir",
    "versions_dirname",
    default="versions",
    show_default=True,
    help="Subdirectory holding ROM-version directories.",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite fantasm.toml if it already exists.",
)
def project_init(
    name: str,
    prefixes: tuple[str, ...],
    at_dirpath: Path,
    cpu: str,
    versions_dirname: str,
    force: bool,
) -> None:
    if not prefixes:
        prefixes = (name,)
    try:
        config = ProjectInitConfig(
            name=name,
            prefixes=prefixes,
            cpu=cpu,
            versions_dirname=versions_dirname,
        )
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    try:
        toml_filepath = init_project(at_dirpath, config, force=force)
    except FileExistsError as exc:
        raise click.UsageError(str(exc)) from exc
    click.echo(f"Wrote {toml_filepath}")
    click.echo(
        f"Versions directory: {at_dirpath / versions_dirname}"
    )


@project.command(
    "add",
    help=(
        "Create a new ROM-version directory under the project. Builds "
        "{versions}/{prefix}-{version_id}/ with rom/ and output/ "
        "subdirectories ready for ROM bytes and disassembly artefacts."
    ),
)
@click.argument("version_id")
@click.option(
    "--prefix",
    help=(
        "Prefix to use for the new version directory. Defaults to the "
        "first prefix in [versions] prefixes."
    ),
)
@click.pass_context
def project_add(
    ctx: click.Context, version_id: str, prefix: str | None
) -> None:
    project_context: ProjectContext = ctx.obj["project"]
    if not project_context.has_root:
        raise click.UsageError(
            "no project root resolved; pass --project-root, set "
            "FANTASM_PROJECT_ROOT, or run from inside a fantasm project"
        )
    versions_dirpath = project_versions_dirpath(project_context)
    if prefix is None:
        configured_prefixes = project_rom_prefixes(project_context)
        if not configured_prefixes:
            raise click.UsageError(
                "no prefix configured; pass --prefix or set "
                "[versions] prefixes in fantasm.toml"
            )
        prefix = configured_prefixes[0]
    try:
        version_dirpath = add_version(versions_dirpath, version_id, prefix)
    except (FileExistsError, ValueError) as exc:
        raise click.UsageError(str(exc)) from exc
    click.echo(f"Created {version_dirpath}")
    click.echo("  rom/    (drop the ROM bytes here)")
    click.echo("  output/ (disassembly artefacts go here)")


@project.command("list", help="List ROM versions registered in the project.")
@report_output(reports={"versions": "ROM versions in this project"})
def project_list() -> Reports:
    project_context: ProjectContext = click.get_current_context().obj["project"]
    table = (
        TableContent(
            title="ROM versions",
            description=(
                str(project_context.root_dirpath)
                if project_context.has_root
                else "(no project root resolved)"
            ),
        )
        .add_column("prefix", "Prefix")
        .add_column("version", "Version")
        .add_column("dirpath", "Path")
    )
    if project_context.has_root:
        versions_dirpath = project_versions_dirpath(project_context)
        prefixes = project_rom_prefixes(project_context)
        for info in list_versions(versions_dirpath, prefixes):
            table.add_row(
                prefix=info.prefix,
                version=info.version_id,
                dirpath=str(info.dirpath),
            )
    return Reports(versions=Report(data=table))
