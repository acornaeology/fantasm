"""Project-layout path resolution.

The four sibling projects each had a tiny ``paths.py`` that hard-coded a
single ROM-name prefix (``adfs``, ``nfs``, ``econet-bridge``, ...) — and
NFS uniquely supported two (``anfs`` / ``nfs``). fantasm generalises that
by reading the prefixes from ``fantasm.toml``.

Schema (under ``[versions]`` in ``fantasm.toml``)::

    [versions]
    directory = "versions"          # default; relative to project root
    prefixes  = ["anfs", "nfs"]     # ordered: first match wins

If ``prefixes`` is omitted the project's ``[project] name`` is used as a
single-element fallback.

The pure helpers (:func:`resolve_version_dirpath`, :func:`rom_prefix`)
take prefix lists explicitly; the ``*_for_project`` wrappers obtain them
from a :class:`fantasm.config.ProjectContext`.

Library code in fantasm raises :class:`VersionNotFoundError` rather than
calling ``sys.exit``; the CLI layer translates the exception into a
clean exit code with a helpful message.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fantasm.config import ProjectContext


DEFAULT_VERSIONS_DIRNAME = "versions"

# Default convention for the per-version py8dis driver script.
# Tokens: {prefix}, {version_id}, {version_id_no_dots}.
# Sibling NFS uses e.g. "disasm_anfs_310.py" for version "3.10".
DEFAULT_DRIVER_DIRNAME = "disassemble"
DEFAULT_DRIVER_FILENAME_TEMPLATE = "disasm_{prefix}_{version_id_no_dots}.py"


def render_driver_filename(
    template: str, prefix: str, version_id: str
) -> str:
    """Render a driver-filename template with project / version tokens.

    Recognised tokens:

    - ``{prefix}``              — the matched ROM prefix
    - ``{version_id}``          — the version ID as written
    - ``{version_id_no_dots}``  — version ID with all ``.`` removed
    """
    return template.format(
        prefix=prefix,
        version_id=version_id,
        version_id_no_dots=version_id.replace(".", ""),
    )


class VersionNotFoundError(LookupError):
    """Raised when no version directory matches the requested ID."""

    def __init__(
        self,
        version_id: str,
        versions_dirpath: Path,
        available: Sequence[str],
    ) -> None:
        self.version_id = version_id
        self.versions_dirpath = versions_dirpath
        self.available: tuple[str, ...] = tuple(available)
        super().__init__(
            f"version {version_id!r} not found under {versions_dirpath}"
        )


def resolve_version_dirpath(
    versions_dirpath: Path,
    version_id: str,
    prefixes: Iterable[str],
) -> Path:
    """Return the directory containing the named version.

    Looks for ``{prefix}-{version_id}`` under ``versions_dirpath`` for
    each prefix in order, returning the first one that exists. Raises
    :class:`VersionNotFoundError` when no candidate matches; the
    exception carries the list of available version directory names so
    a caller can render a helpful error.
    """
    prefix_list = list(prefixes)
    for prefix in prefix_list:
        candidate_dirpath = versions_dirpath / f"{prefix}-{version_id}"
        if candidate_dirpath.is_dir():
            return candidate_dirpath
    if versions_dirpath.is_dir():
        available = sorted(
            entry.name for entry in versions_dirpath.iterdir() if entry.is_dir()
        )
    else:
        available = []
    raise VersionNotFoundError(version_id, versions_dirpath, available)


def rom_prefix(version_dirpath: Path, prefixes: Iterable[str]) -> str:
    """Return the ROM prefix matched by ``version_dirpath``'s name.

    For example, with prefixes ``("anfs", "nfs")`` and a directory
    named ``anfs-3.10``, returns ``"anfs"``. Multi-hyphen prefixes like
    ``tube-6502-client`` are matched eagerly, so
    ``tube-6502-client-1.10`` returns ``"tube-6502-client"``.

    Falls back to the substring before the last hyphen if no configured
    prefix matches — this preserves the old behaviour for callers
    operating on arbitrary directory names.
    """
    name = version_dirpath.name
    for prefix in prefixes:
        if name == prefix or name.startswith(f"{prefix}-"):
            return prefix
    if "-" in name:
        return name.rsplit("-", 1)[0]
    return name


# --- Project-aware wrappers -----------------------------------------


def project_versions_dirpath(project: ProjectContext) -> Path:
    """Return the project's versions directory.

    Reads ``[versions] directory`` from ``fantasm.toml`` (defaulting to
    ``"versions"``), resolved against the project root.

    Raises ``RuntimeError`` if the project root has not been resolved.
    """
    if not project.has_root or project.root_dirpath is None:
        raise RuntimeError(
            "Project root is not resolved; pass --project-root, set "
            "FANTASM_PROJECT_ROOT, or run from inside a directory tree "
            "containing fantasm.toml."
        )
    versions_section = project.config.get("versions", {})
    relative = versions_section.get("directory", DEFAULT_VERSIONS_DIRNAME)
    return project.root_dirpath / relative


def project_rom_prefixes(project: ProjectContext) -> tuple[str, ...]:
    """Return the configured ROM-name prefixes for the project.

    Reads ``[versions] prefixes`` from ``fantasm.toml``. If unset, falls
    back to ``[project] name``. If neither is set, returns an empty
    tuple — callers should treat that as a configuration error.
    """
    versions_section = project.config.get("versions", {})
    prefixes = versions_section.get("prefixes")
    if prefixes:
        return tuple(prefixes)
    project_section = project.config.get("project", {})
    name = project_section.get("name")
    if name:
        return (name,)
    return ()


def resolve_version_dirpath_for_project(
    project: ProjectContext, version_id: str
) -> Path:
    """Resolve a version directory using project-configured prefixes."""
    versions_dirpath = project_versions_dirpath(project)
    prefixes = project_rom_prefixes(project)
    return resolve_version_dirpath(versions_dirpath, version_id, prefixes)


def rom_prefix_for_project(
    project: ProjectContext, version_dirpath: Path
) -> str:
    """Extract a ROM prefix using project-configured prefixes."""
    return rom_prefix(version_dirpath, project_rom_prefixes(project))


def project_driver_dirname(project: ProjectContext) -> str:
    """Return the project's driver-script subdirectory name.

    Reads ``[versions] driver_dirname`` from ``fantasm.toml``,
    defaulting to ``"disassemble"``.
    """
    versions_section = project.config.get("versions", {})
    return versions_section.get("driver_dirname", DEFAULT_DRIVER_DIRNAME)


def project_driver_filename_template(project: ProjectContext) -> str:
    """Return the project's driver-filename template.

    Reads ``[versions] driver_filename`` from ``fantasm.toml``.
    Default: ``"disasm_{prefix}_{version_id_no_dots}.py"``.
    """
    versions_section = project.config.get("versions", {})
    return versions_section.get(
        "driver_filename", DEFAULT_DRIVER_FILENAME_TEMPLATE
    )


__all__ = [
    "DEFAULT_DRIVER_DIRNAME",
    "DEFAULT_DRIVER_FILENAME_TEMPLATE",
    "DEFAULT_VERSIONS_DIRNAME",
    "VersionNotFoundError",
    "project_driver_dirname",
    "project_driver_filename_template",
    "project_rom_prefixes",
    "project_versions_dirpath",
    "render_driver_filename",
    "resolve_version_dirpath",
    "resolve_version_dirpath_for_project",
    "rom_prefix",
    "rom_prefix_for_project",
]
