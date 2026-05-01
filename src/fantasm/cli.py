"""Click-based command-line entrypoint for fantasm."""

from __future__ import annotations

from pathlib import Path

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from . import __version__
from .api.paths import project_rom_prefixes, project_versions_dirpath
from .api.project import (
    ProjectInitConfig,
    add_version,
    init_project,
    list_versions,
)
from .config import ProjectContext, resolve_project_context


@click.group(
    help="Fantasm — the Fantastic (dis-/re-)Assembly tools for 6502 code.",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(__version__, prog_name="fantasm")
@click.option(
    "--project-root",
    "project_root_dirpath",
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    envvar="FANTASM_PROJECT_ROOT",
    help=(
        "Project root directory. Overrides FANTASM_PROJECT_ROOT. "
        "If neither is given, fantasm searches upwards from the current "
        "directory for a fantasm.toml."
    ),
)
@click.pass_context
def main(ctx: click.Context, project_root_dirpath: Path | None) -> None:
    ctx.ensure_object(dict)
    ctx.obj["project"] = resolve_project_context(project_root_dirpath)


@main.command(help="Show the resolved project context.")
@report_output(reports={"project": "Resolved project context"})
def info() -> Reports:
    project: ProjectContext = click.get_current_context().obj["project"]
    table = (
        TableContent(
            title="Fantasm project",
            description="Resolved project context for the current invocation.",
        )
        .add_column("key", "Key")
        .add_column("value", "Value")
        .add_row(
            key="project_root",
            value=str(project.root_dirpath) if project.root_dirpath else "(unresolved)",
        )
        .add_row(
            key="config_filepath",
            value=str(project.config_filepath) if project.config_filepath else "(none)",
        )
        .add_row(
            key="config_keys",
            value=", ".join(sorted(project.config)) if project.config else "(empty)",
        )
    )
    return Reports(project=Report(data=table))


@main.group(help="Initialise and manage fantasm projects.")
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
    click.echo(f"  rom/    (drop the ROM bytes here)")
    click.echo(f"  output/ (disassembly artefacts go here)")


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


if __name__ == "__main__":  # pragma: no cover
    main()
