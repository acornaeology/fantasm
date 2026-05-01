"""Click-based command-line entrypoint for fantasm."""

from __future__ import annotations

from pathlib import Path

import click
from asyoulikeit import Report, Reports, TableContent, report_output

from . import __version__
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


if __name__ == "__main__":  # pragma: no cover
    main()
