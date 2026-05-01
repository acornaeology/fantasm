"""Shared helpers for fantasm CLI commands.

Per-version file resolution, project-config readers, and an
``AnalysisContext`` that lazily loads the recurring JSON-data /
memory-regions / subroutines / call-graph / asm-lines bundle so
commands don't have to keep repeating the boilerplate.

Errors from the api layer are translated to ``click.UsageError`` so
the user sees a clean message rather than a Python traceback.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Any

import click

from .api.audit import build_memory_regions, load_subroutines
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


def project_cpu(project_context: ProjectContext) -> str:
    """Return the project's default CPU from ``[rom] cpu``.

    Falls back to ``"6502"`` when unset or when the project root
    isn't resolved.
    """
    rom_section = project_context.config.get("rom", {})
    return rom_section.get("cpu", "6502")


def project_rom_base(project_context: ProjectContext) -> int:
    """Return the project's default ROM load address from ``[rom] base_address``.

    Falls back to ``0x8000`` (BBC sideways-ROM convention) when unset.
    """
    rom_section = project_context.config.get("rom", {})
    return rom_section.get("base_address", 0x8000)


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


# --- AnalysisContext ----------------------------------------------


@dataclass
class AnalysisContext:
    """Lazy-loaded per-version analysis data for CLI commands.

    Wraps the recurring "resolve files → load JSON → build memory
    regions → load subroutines / call graph / asm lines" sequence
    behind cached properties. Commands ask for only what they need;
    the file IO + parsing happens once per attribute on first
    access.

    Use :func:`analysis_context` to construct one from a Click
    context plus a version id.
    """

    project: ProjectContext
    version_id: str
    files: VersionFiles

    @cached_property
    def data(self) -> dict:
        """Parsed JSON disassembly output for this version.

        Raises ``click.UsageError`` if the JSON file is missing.
        """
        if not self.files.json_filepath.exists():
            raise click.UsageError(
                f"JSON not found: {self.files.json_filepath} "
                "(run disassemble first)"
            )
        return json.loads(self.files.json_filepath.read_text())

    @cached_property
    def base_regions(self) -> list[tuple[int, int]]:
        """Workspace + external regions for this version, from the graph."""
        return effective_regions_for(self.project, self.version_id)

    @cached_property
    def memory_regions(self) -> list[tuple[int, int]]:
        """Full memory regions: base regions ∪ ROM range from JSON metadata."""
        return build_memory_regions(
            self.data["meta"], base_regions=self.base_regions
        )

    @cached_property
    def audit_subs(self) -> list[dict]:
        """Subroutines loaded with project-aware memory regions."""
        return load_subroutines(
            self.files.json_filepath,
            memory_regions=self.memory_regions,
        )

    @cached_property
    def call_graph(self) -> Any:
        """Inter-procedural call graph (networkx DiGraph)."""
        # Imported here to avoid a top-level networkx dep on this
        # module when callers only need data/audit_subs/asm_lines.
        from .api.cfg import build_call_graph

        return build_call_graph(
            self.files.json_filepath,
            memory_regions=self.memory_regions,
        )

    @cached_property
    def asm_lines(self) -> list[str]:
        """Assembly file lines (with line endings preserved).

        Raises ``click.UsageError`` if the ASM file is missing.
        """
        if not self.files.asm_filepath.exists():
            raise click.UsageError(
                f"ASM not found: {self.files.asm_filepath} "
                "(run disassemble first)"
            )
        return self.files.asm_filepath.read_text().splitlines(keepends=True)


def analysis_context(
    ctx: click.Context, version_id: str
) -> AnalysisContext:
    """Construct an :class:`AnalysisContext` from a Click context."""
    project = require_project(ctx)
    files = resolve_version_files(project, version_id)
    return AnalysisContext(
        project=project, version_id=version_id, files=files
    )


__all__ = [
    "AnalysisContext",
    "VersionFiles",
    "analysis_context",
    "effective_regions_for",
    "project_cpu",
    "project_rom_base",
    "require_project",
    "resolve_version_files",
]
