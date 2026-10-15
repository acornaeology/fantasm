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
from dataclasses import dataclass
from functools import cached_property
from typing import Any, Callable

import click

from .api.audit import build_memory_regions, load_subroutines
from .api.inf import InfParseError
from .api.paths import (
    VersionNotFoundError,
    project_binary_base,
    project_cpu,
)
from .api.targets import (
    TargetConfigError,
    TargetFiles,
    TargetNotFoundError,
    resolve_target,
)
from .api.version_graph import (
    VersionGraphError,
    VersionNotInGraphError,
    load_version_graph,
)
from .config import ProjectContext


# Kept under its historical name: every per-version command works on
# a target, and a version is just a target in the version graph.
VersionFiles = TargetFiles


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
) -> TargetFiles:
    """Resolve the files for a given target (``version_id``).

    Delegates to :func:`fantasm.api.targets.resolve_target`, which
    applies the ``versions/`` convention, ``[layout]`` templates and
    ``[[targets]]`` entries in turn. Files are not required to exist;
    commands check what they need.

    Raises ``click.UsageError`` if the target is unknown (with the
    available targets listed), if its configuration is invalid, or if
    its ``.inf`` sidecar can't be parsed.
    """
    try:
        return resolve_target(project_context, version_id)
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
    except (TargetNotFoundError, TargetConfigError, InfParseError) as exc:
        raise click.UsageError(str(exc)) from exc


def target_load_address(
    project_context: ProjectContext, files: TargetFiles
) -> int:
    """The target's load address, falling back to ``[binary] base_address``."""
    if files.load_address is not None:
        return files.load_address
    return project_binary_base(project_context)


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


def make_binary_loader(
    project_context: ProjectContext,
) -> Callable[[str], bytes]:
    """Return a memoised program-binary loader keyed by version id.

    Used by cross-version commands (backfill, annotations diff) that
    walk the version graph and need to read each visited version's
    binary bytes. The cache lives in the closure, so each command
    invocation gets its own loader — caching is local to a single CLI
    run, not process-global.

    Raises ``click.UsageError`` if a version's binary file is missing.
    """
    cache: dict[str, bytes] = {}

    def loader(version_id: str) -> bytes:
        if version_id not in cache:
            files = resolve_version_files(project_context, version_id)
            if not files.binary_filepath.exists():
                raise click.UsageError(
                    f"binary not found: {files.binary_filepath}"
                )
            cache[version_id] = files.binary_filepath.read_bytes()
        return cache[version_id]

    return loader


__all__ = [
    "AnalysisContext",
    "VersionFiles",
    "analysis_context",
    "effective_regions_for",
    "make_binary_loader",
    "project_binary_base",
    "project_cpu",
    "require_project",
    "resolve_version_files",
    "target_load_address",
]
