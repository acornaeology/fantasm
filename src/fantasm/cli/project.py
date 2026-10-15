"""``fantasm project`` — initialise and manage fantasm projects."""

from __future__ import annotations

from pathlib import Path

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from ..api.inf import InfParseError
from ..api.paths import (
    project_binary_dirname,
    project_rom_prefixes,
    project_versions_dirpath,
)
from ..api.project import (
    PROJECT_LAYOUTS,
    ProjectInitConfig,
    TargetSpec,
    add_version,
    append_target,
    binary_addresses,
    default_target_paths,
    init_project,
    parse_binary_option,
    project_relative,
)
from ..api.targets import TargetConfigError, list_target_ids
from ..cli_helpers import resolve_version_files, target_load_address
from ..config import ProjectContext
from ._target import FantasmGroup


@click.group(cls=FantasmGroup, help="Initialise and manage fantasm projects.")
def project() -> None:
    pass


def _target_options(func):
    """The options describing one explicitly-laid-out target."""
    options = [
        click.option(
            "--binary",
            "binary_option",
            metavar="PATH[@ADDR]",
            help=(
                "The program binary, optionally with its hexadecimal load "
                "address (e.g. disc/FS3@1900). Without @ADDR the load and "
                "exec addresses are read from the binary's .inf sidecar."
            ),
        ),
        click.option(
            "--driver",
            "driver_path",
            help="Driver script path (default disasm_<id>.py).",
        ),
        click.option(
            "--asm",
            "asm_path",
            help="Generated .asm path (default output/<id>.asm).",
        ),
        click.option(
            "--json",
            "json_path",
            help="Generated .json path (default output/<id>.json).",
        ),
        click.option(
            "--metadata",
            "metadata_path",
            help="Optional metadata JSON path (its docs list is linted).",
        ),
    ]
    for option in reversed(options):
        func = option(func)
    return func


def _target_spec(
    root_dirpath: Path,
    target_id: str,
    binary_option: str,
    driver_path: str | None,
    asm_path: str | None,
    json_path: str | None,
    metadata_path: str | None,
) -> TargetSpec:
    """Build a :class:`TargetSpec`, reading the .inf when needed.

    Paths given on the command line are relative to the current
    directory; they are written to fantasm.toml relative to the
    project root.
    """
    try:
        binary_text, load_address = parse_binary_option(binary_option)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    binary_filepath = Path(binary_text)
    if load_address is None and not binary_filepath.exists():
        raise click.UsageError(f"binary not found: {binary_filepath}")
    try:
        load, exec_address, inf_filepath = binary_addresses(
            binary_filepath, load_address
        )
    except InfParseError as exc:
        raise click.UsageError(str(exc)) from exc

    defaults = default_target_paths(target_id)

    def relative(given: str | None, default: str) -> str:
        if given is None:
            return default
        return project_relative(Path(given), root_dirpath)

    try:
        return TargetSpec(
            id=target_id,
            binary=project_relative(binary_filepath, root_dirpath),
            load_address=load,
            exec_address=exec_address,
            driver=relative(driver_path, defaults["driver"]),
            asm=relative(asm_path, defaults["asm"]),
            json=relative(json_path, defaults["json"]),
            metadata=(
                project_relative(Path(metadata_path), root_dirpath)
                if metadata_path is not None
                else None
            ),
            inf_source=(
                project_relative(inf_filepath, root_dirpath)
                if inf_filepath is not None
                else None
            ),
        )
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc


@project.command(
    "init",
    help=(
        "Initialise a fantasm project. With the default --layout "
        "versions, write fantasm.toml and create the versions "
        "directory. With --layout explicit, adopt an existing project "
        "as it stands: write fantasm.toml with a [[targets]] entry "
        "naming the binary (--binary), driver, .asm and .json where "
        "they already are, and create nothing else. Safe to run inside "
        "an existing repository: no existing files are touched apart "
        "from fantasm.toml."
    ),
)
@click.option("--name", required=True, help="Project name.")
@click.option(
    "--layout",
    type=click.Choice(PROJECT_LAYOUTS),
    default="versions",
    show_default=True,
    help=(
        "versions: one directory per version under the versions "
        "directory. explicit: a [[targets]] entry with the given paths."
    ),
)
@click.option(
    "--prefix",
    "prefixes",
    multiple=True,
    help=(
        "Version-directory name prefix. Repeat for multi-prefix "
        "projects (e.g. NFS's anfs/nfs). Defaults to the project name "
        "when omitted."
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
    help="Subdirectory holding the version directories (versions layout).",
)
@click.option(
    "--target",
    "target_id",
    help="Target id for --layout explicit (default: the project name).",
)
@_target_options
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite fantasm.toml if it already exists.",
)
def project_init(
    name: str,
    layout: str,
    prefixes: tuple[str, ...],
    at_dirpath: Path,
    cpu: str,
    versions_dirname: str,
    target_id: str | None,
    binary_option: str | None,
    driver_path: str | None,
    asm_path: str | None,
    json_path: str | None,
    metadata_path: str | None,
    force: bool,
) -> None:
    if not prefixes:
        prefixes = (name,)
    targets: tuple[TargetSpec, ...] = ()
    explicit_given = any(
        value is not None
        for value in (target_id, binary_option, driver_path, asm_path,
                      json_path, metadata_path)
    )
    if layout == "explicit":
        if binary_option is None:
            raise click.UsageError("--layout explicit needs --binary")
        targets = (
            _target_spec(
                at_dirpath,
                target_id or name,
                binary_option,
                driver_path,
                asm_path,
                json_path,
                metadata_path,
            ),
        )
    elif explicit_given:
        raise click.UsageError(
            "--target, --binary, --driver, --asm, --json and --metadata "
            "need --layout explicit"
        )
    try:
        config = ProjectInitConfig(
            name=name,
            prefixes=prefixes,
            cpu=cpu,
            versions_dirname=versions_dirname,
            layout=layout,
            targets=targets,
        )
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    try:
        toml_filepath = init_project(at_dirpath, config, force=force)
    except FileExistsError as exc:
        raise click.UsageError(str(exc)) from exc
    click.echo(f"Wrote {toml_filepath}")
    if layout == "explicit":
        spec = targets[0]
        click.echo(
            f"Target {spec.id}: {spec.binary} at &{spec.load_address:04X}"
        )
    else:
        click.echo(
            f"Versions directory: {at_dirpath / versions_dirname}"
        )


@project.command(
    "add",
    help=(
        "Add a target to the project. Without --binary, create a new "
        "version directory {versions}/{prefix}-{ID}/ with the "
        "configured binary subdirectory ([binary] dir, default rom/) "
        "and output/, ready for the binary bytes and disassembly "
        "artefacts. With --binary, append a [[targets]] entry to "
        "fantasm.toml naming the files where they already are."
    ),
)
@click.argument("new_id", metavar="ID")
@click.option(
    "--prefix",
    help=(
        "Prefix to use for the new version directory. Defaults to the "
        "first prefix in [versions] prefixes."
    ),
)
@_target_options
@click.pass_context
def project_add(
    ctx: click.Context,
    new_id: str,
    prefix: str | None,
    binary_option: str | None,
    driver_path: str | None,
    asm_path: str | None,
    json_path: str | None,
    metadata_path: str | None,
) -> None:
    project_context: ProjectContext = ctx.obj["project"]
    if not project_context.has_root:
        raise click.UsageError(
            "no project root resolved; pass --project-root, set "
            "FANTASM_PROJECT_ROOT, or run from inside a fantasm project"
        )

    if any(
        value is not None
        for value in (binary_option, driver_path, asm_path, json_path,
                      metadata_path)
    ):
        if binary_option is None:
            raise click.UsageError(
                "--driver, --asm, --json and --metadata need --binary"
            )
        if prefix is not None:
            raise click.UsageError("--prefix doesn't apply with --binary")
        _add_explicit_target(
            project_context, new_id, binary_option, driver_path, asm_path,
            json_path, metadata_path,
        )
        return

    versions_dirpath = project_versions_dirpath(project_context)
    if prefix is None:
        configured_prefixes = project_rom_prefixes(project_context)
        if not configured_prefixes:
            raise click.UsageError(
                "no prefix configured; pass --prefix or set "
                "[versions] prefixes in fantasm.toml"
            )
        prefix = configured_prefixes[0]
    binary_dirname = project_binary_dirname(project_context)
    try:
        version_dirpath = add_version(
            versions_dirpath, new_id, prefix, binary_dirname
        )
    except (FileExistsError, ValueError) as exc:
        raise click.UsageError(str(exc)) from exc
    click.echo(f"Created {version_dirpath}")
    click.echo(f"  {binary_dirname}/ (drop the binary bytes here)")
    click.echo("  output/ (disassembly artefacts go here)")


def _add_explicit_target(
    project_context: ProjectContext,
    target_id: str,
    binary_option: str,
    driver_path: str | None,
    asm_path: str | None,
    json_path: str | None,
    metadata_path: str | None,
) -> None:
    if project_context.config_filepath is None:
        raise click.UsageError(
            "no fantasm.toml to add to; run fantasm project init first"
        )
    assert project_context.root_dirpath is not None
    try:
        known = list_target_ids(project_context)
    except TargetConfigError as exc:
        raise click.UsageError(str(exc)) from exc
    if target_id in known:
        raise click.UsageError(f"target {target_id!r} already exists")
    spec = _target_spec(
        project_context.root_dirpath, target_id, binary_option,
        driver_path, asm_path, json_path, metadata_path,
    )
    try:
        append_target(project_context.config_filepath, spec)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    click.echo(
        f"Added target {spec.id} to {project_context.config_filepath}: "
        f"{spec.binary} at &{spec.load_address:04X}"
    )


@project.command(
    "list",
    help=(
        "List the project's targets: [[targets]] entries, versions "
        "named by [layout], and version directories."
    ),
)
@report_output(reports={"targets": "Targets in this project"})
def project_list() -> Reports:
    project_context: ProjectContext = click.get_current_context().obj["project"]
    table = (
        TableContent(
            title="Targets",
            description=(
                str(project_context.root_dirpath)
                if project_context.has_root
                else "(no project root resolved)"
            ),
        )
        .add_column("target", "Target")
        .add_column("prefix", "Prefix")
        .add_column("source", "Source")
        .add_column("load", "Load")
        .add_column("binary", "Binary")
        .add_column("dirpath", "Path")
    )
    if not project_context.has_root:
        return Reports(targets=Report(data=table))
    try:
        target_ids = list_target_ids(project_context)
    except TargetConfigError as exc:
        raise click.UsageError(str(exc)) from exc
    for target_id in target_ids:
        try:
            files = resolve_version_files(project_context, target_id)
        except click.UsageError as exc:
            table.add_row(
                target=target_id, prefix="", source="", load="",
                binary=f"(error: {exc.message})", dirpath="",
            )
            continue
        table.add_row(
            target=target_id,
            prefix=files.prefix,
            source=files.source,
            load=f"&{target_load_address(project_context, files):04X}",
            binary=str(files.binary_filepath),
            dirpath=str(files.version_dirpath),
        )
    return Reports(targets=Report(data=table))
