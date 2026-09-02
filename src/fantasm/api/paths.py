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

from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fantasm.config import ProjectContext


DEFAULT_VERSIONS_DIRNAME = "versions"

# Defaults for the per-version binary layout. These reproduce the
# historical ROM-image convention, so a project with only a ``[rom]``
# section (or none at all) is unaffected.
DEFAULT_BINARY_DIRNAME = "rom"
DEFAULT_BINARY_EXTENSION = "rom"
DEFAULT_BINARY_METADATA_FILENAME = "rom.json"
DEFAULT_CPU = "6502"
DEFAULT_BASE_ADDRESS = 0x8000

# Default convention for the per-version disassembly driver script
# (whether built on dasmos, py8dis, or any other library).
# Tokens: {prefix}, {version_id}, {version_id_no_dots}.
# Sibling NFS uses e.g. "disasm_anfs_310.py" for version "3.10".
DEFAULT_DRIVER_DIRNAME = "disassemble"
DEFAULT_DRIVER_FILENAME_TEMPLATE = "disasm_{prefix}_{version_id_no_dots}.py"

# Default convention for the per-version binary basename (the extension,
# if any, is appended afterwards). Same token set as the driver template.
# Default reproduces the historical ``{prefix}-{version_id}`` name.
DEFAULT_BINARY_FILENAME_TEMPLATE = "{prefix}-{version_id}"


def _filename_tokens(prefix: str, version_id: str) -> dict[str, str]:
    """Build the token substitutions shared by the filename renderers.

    Recognised tokens:

    - ``{prefix}`` / ``{prefix_upper}`` / ``{prefix_lower}``
    - ``{version_id}``          — the version ID as written
    - ``{version_id_no_dots}``  — version ID with all ``.`` removed
    - ``{version_id_upper}`` / ``{version_id_lower}`` — case variants
    """
    return {
        "prefix": prefix,
        "prefix_upper": prefix.upper(),
        "prefix_lower": prefix.lower(),
        "version_id": version_id,
        "version_id_no_dots": version_id.replace(".", ""),
        "version_id_upper": version_id.upper(),
        "version_id_lower": version_id.lower(),
    }


def render_driver_filename(
    template: str, prefix: str, version_id: str
) -> str:
    """Render a driver-filename template with project / version tokens.

    See :func:`_filename_tokens` for the recognised tokens.
    """
    return template.format(**_filename_tokens(prefix, version_id))


def render_binary_filename(
    template: str, prefix: str, version_id: str
) -> str:
    """Render a binary-basename template with project / version tokens.

    Same token set as :func:`render_driver_filename` (see
    :func:`_filename_tokens`). The binary's extension, if any, is
    appended by the caller after the rendered basename.
    """
    return template.format(**_filename_tokens(prefix, version_id))


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


def project_binary_section(project: ProjectContext) -> Mapping[str, Any]:
    """Return the project's binary-layout config section.

    Reads ``[binary]`` from ``fantasm.toml`` when present, else falls
    back to the historical ``[rom]`` section, else an empty mapping.
    The two are not merged — whichever section is present wins — so a
    project migrating to ``[binary]`` should move all of its keys.
    """
    config = project.config
    if "binary" in config:
        return config.get("binary", {})
    return config.get("rom", {})


def project_cpu(project: ProjectContext) -> str:
    """Return the project's default CPU (``cpu`` key).

    Reads ``[binary] cpu`` (or ``[rom] cpu``), defaulting to ``"6502"``.
    """
    return project_binary_section(project).get("cpu", DEFAULT_CPU)


def project_binary_base(project: ProjectContext) -> int:
    """Return the project's default load address (``base_address`` key).

    Reads ``[binary] base_address`` (or ``[rom] base_address``),
    defaulting to ``0x8000`` (the BBC sideways-ROM convention).
    """
    return project_binary_section(project).get(
        "base_address", DEFAULT_BASE_ADDRESS
    )


def project_binary_dirname(project: ProjectContext) -> str:
    """Return the per-version binary subdirectory name (``dir`` key).

    Reads ``[binary] dir`` (or ``[rom] dir``), defaulting to ``"rom"``.
    """
    return project_binary_section(project).get(
        "dir", DEFAULT_BINARY_DIRNAME
    )


def project_binary_extension(project: ProjectContext) -> str:
    """Return the binary file extension, without a leading dot.

    Reads ``[binary] extension`` (or ``[rom] extension``), defaulting
    to ``"rom"``. An empty string means the binary has no extension
    (e.g. a DFS ``*RUN`` program named ``KEYPAD``).
    """
    return project_binary_section(project).get(
        "extension", DEFAULT_BINARY_EXTENSION
    )


def project_binary_metadata_filename(project: ProjectContext) -> str:
    """Return the per-version metadata filename (``metadata`` key).

    Reads ``[binary] metadata`` (or ``[rom] metadata``), defaulting to
    ``"rom.json"``. The file lives in the binary subdirectory.
    """
    return project_binary_section(project).get(
        "metadata", DEFAULT_BINARY_METADATA_FILENAME
    )


def project_binary_filename_template(project: ProjectContext) -> str:
    """Return the binary-basename template (``filename`` key).

    Reads ``[binary] filename`` (or ``[rom] filename``), defaulting to
    ``"{prefix}-{version_id}"``. Rendered by
    :func:`render_binary_filename`; the extension (if any) is appended
    afterwards. Set e.g. ``"{version_id_upper}"`` to keep an Acorn
    DFS-style name like ``KEYPAD`` from the id ``keypad``.
    """
    return project_binary_section(project).get(
        "filename", DEFAULT_BINARY_FILENAME_TEMPLATE
    )


__all__ = [
    "DEFAULT_BASE_ADDRESS",
    "DEFAULT_BINARY_DIRNAME",
    "DEFAULT_BINARY_EXTENSION",
    "DEFAULT_BINARY_FILENAME_TEMPLATE",
    "DEFAULT_BINARY_METADATA_FILENAME",
    "DEFAULT_CPU",
    "DEFAULT_DRIVER_DIRNAME",
    "DEFAULT_DRIVER_FILENAME_TEMPLATE",
    "DEFAULT_VERSIONS_DIRNAME",
    "VersionNotFoundError",
    "project_binary_base",
    "project_binary_dirname",
    "project_binary_extension",
    "project_binary_filename_template",
    "project_binary_metadata_filename",
    "project_binary_section",
    "project_cpu",
    "project_driver_dirname",
    "project_driver_filename_template",
    "project_rom_prefixes",
    "project_versions_dirpath",
    "render_binary_filename",
    "render_driver_filename",
    "resolve_version_dirpath",
    "resolve_version_dirpath_for_project",
    "rom_prefix",
    "rom_prefix_for_project",
]
