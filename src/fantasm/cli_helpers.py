"""Shared helpers for fantasm CLI commands.

Per-version file resolution and a thin error-translation wrapper that
maps the api's typed exceptions to ``click.UsageError`` so the user
sees a clean message rather than a Python traceback.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import click

from .api.paths import (
    VersionNotFoundError,
    project_driver_dirname,
    project_driver_filename_template,
    project_rom_prefixes,
    project_versions_dirpath,
    render_driver_filename,
    resolve_version_dirpath,
)
from .api.version_graph import (
    VersionGraphError,
    VersionNotInGraphError,
    load_version_graph,
)
from .config import ProjectContext


@dataclass(frozen=True)
class VersionFiles:
    """Conventional file paths inside a version directory.

    ``versions/{prefix}-{version_id}/`` is the version directory; the
    ROM lives under ``rom/{prefix}-{version_id}.rom`` and disassembly
    artefacts under ``output/{prefix}-{version_id}.{asm,json}``. The
    driver script's path is derived from
    ``[versions] driver_dirname`` and ``[versions] driver_filename``
    (defaults: ``disassemble/`` and
    ``disasm_{prefix}_{version_id_no_dots}.py``).
    """

    version_id: str
    prefix: str
    version_dirpath: Path
    rom_filepath: Path
    asm_filepath: Path
    json_filepath: Path
    driver_filepath: Path


def require_project(ctx: click.Context) -> ProjectContext:
    """Return the resolved project context or raise UsageError."""
    project_context: ProjectContext = ctx.obj["project"]
    if not project_context.has_root:
        raise click.UsageError(
            "no project root resolved; pass --project-root, set "
            "FANTASM_PROJECT_ROOT, or run from inside a fantasm project"
        )
    return project_context


def resolve_version_files(
    project_context: ProjectContext, version_id: str
) -> VersionFiles:
    """Resolve the conventional files for a given ``version_id``.

    Walks the project's configured prefixes and returns paths for the
    ROM bytes, the assembled output, and the JSON manifest. Files are
    not required to exist; commands check what they need.

    Raises ``click.UsageError`` if the version directory is missing
    (with the available versions listed) or if the project's prefixes
    are unconfigured.
    """
    versions_dirpath = project_versions_dirpath(project_context)
    prefixes = project_rom_prefixes(project_context)
    if not prefixes:
        raise click.UsageError(
            "no [versions] prefixes configured in fantasm.toml "
            "(and no [project] name to fall back on)"
        )

    try:
        version_dirpath = resolve_version_dirpath(
            versions_dirpath, version_id, prefixes
        )
    except VersionNotFoundError as exc:
        suffix = (
            f"\nAvailable: {', '.join(exc.available)}"
            if exc.available
            else ""
        )
        raise click.UsageError(
            f"version {version_id!r} not found under "
            f"{exc.versions_dirpath}{suffix}"
        ) from exc

    # Determine which configured prefix matched.
    name = version_dirpath.name
    matched_prefix = next(
        (p for p in prefixes if name == p or name.startswith(f"{p}-")),
        prefixes[0],
    )

    base = f"{matched_prefix}-{version_id}"
    driver_dirname = project_driver_dirname(project_context)
    driver_filename = render_driver_filename(
        project_driver_filename_template(project_context),
        matched_prefix,
        version_id,
    )
    return VersionFiles(
        version_id=version_id,
        prefix=matched_prefix,
        version_dirpath=version_dirpath,
        rom_filepath=version_dirpath / "rom" / f"{base}.rom",
        asm_filepath=version_dirpath / "output" / f"{base}.asm",
        json_filepath=version_dirpath / "output" / f"{base}.json",
        driver_filepath=version_dirpath / driver_dirname / driver_filename,
    )


def effective_regions_for(
    project_context: ProjectContext, version_id: str
) -> list[tuple[int, int]]:
    """Return the project-graph's effective regions for ``version_id``.

    Combines the version's ``effective_regions`` (workspace) with
    ``effective_external_regions`` (hardware / OS) and converts the
    :class:`Region` dataclasses to ``(start, end)`` tuples, the
    format the audit / lint / comment_check api modules consume.

    Returns ``[]`` when there's no version graph at all, when the
    graph is empty, or when ``version_id`` isn't declared in it.
    Commands that observe the empty result fall back to ROM-only
    region awareness — which is the right behaviour for projects
    that don't use the version-graph features yet.
    """
    try:
        graph = load_version_graph(project_context)
    except VersionGraphError:
        return []
    if version_id not in graph:
        return []
    regions = graph.effective_regions(version_id)
    external = graph.effective_external_regions(version_id)
    return [(r.start, r.end) for r in regions + external]


__all__ = [
    "VersionFiles",
    "effective_regions_for",
    "require_project",
    "resolve_version_files",
]
