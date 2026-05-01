"""Project scaffolding.

Helpers to initialise a new fantasm project (write ``fantasm.toml``,
create the standard ``versions/`` directory) and to add or list ROM
versions in an existing project.

Pure helpers; the ``fantasm project`` Click sub-commands wrap these.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


CONFIG_FILENAME = "fantasm.toml"
VERSIONS_DIRNAME_DEFAULT = "versions"
VALID_PREFIX_RE = re.compile(r"^[A-Za-z0-9_-]+$")


@dataclass(frozen=True)
class ProjectInitConfig:
    """Configuration for initialising a fantasm project.

    ``prefixes`` must contain at least one entry. Each prefix matches
    the regex ``[A-Za-z0-9_-]+`` (no spaces, no slashes).
    """

    name: str
    prefixes: tuple[str, ...]
    versions_dirname: str = VERSIONS_DIRNAME_DEFAULT
    cpu: str = "6502"

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("project name is required")
        if not self.prefixes:
            raise ValueError("at least one prefix is required")
        for prefix in self.prefixes:
            if not VALID_PREFIX_RE.match(prefix):
                raise ValueError(f"invalid prefix {prefix!r}")
        if not VALID_PREFIX_RE.match(self.versions_dirname):
            raise ValueError(
                f"invalid versions directory name {self.versions_dirname!r}"
            )


@dataclass(frozen=True)
class VersionInfo:
    """A discovered ROM-version directory."""

    prefix: str
    version_id: str
    dirpath: Path


def render_fantasm_toml(config: ProjectInitConfig) -> str:
    """Render the ``fantasm.toml`` content for a new project.

    Output is hand-formatted (with comments) rather than serialised by
    a TOML library, so the file is still readable when a human edits
    it later.
    """
    prefix_literal = ", ".join(f'"{p}"' for p in config.prefixes)
    lines = [
        "# fantasm project configuration. See docs/configuration.md for the schema.",
        "",
        "[project]",
        f'name = "{config.name}"',
        "",
        "[rom]",
        f'# Default CPU for opcode decoding: "6502" (NMOS) or "65c02" (CMOS).',
        f'cpu = "{config.cpu}"',
        "",
        "[versions]",
    ]
    if config.versions_dirname != VERSIONS_DIRNAME_DEFAULT:
        lines.append(f'directory = "{config.versions_dirname}"')
    lines.append(f"prefixes = [{prefix_literal}]")
    lines.append("")
    return "\n".join(lines)


def init_project(
    root_dirpath: Path,
    config: ProjectInitConfig,
    *,
    force: bool = False,
) -> Path:
    """Initialise a fantasm project at ``root_dirpath``.

    Writes ``fantasm.toml`` and ensures the versions directory exists
    (creating it with a ``.gitkeep`` if it didn't). Returns the
    ``fantasm.toml`` path.

    Raises ``FileExistsError`` if ``fantasm.toml`` already exists and
    ``force=False``. Other files in ``root_dirpath`` are left
    untouched, so it is safe to run inside an existing repository.
    """
    root_dirpath = Path(root_dirpath)
    root_dirpath.mkdir(parents=True, exist_ok=True)

    fantasm_toml_filepath = root_dirpath / CONFIG_FILENAME
    if fantasm_toml_filepath.exists() and not force:
        raise FileExistsError(
            f"{fantasm_toml_filepath} already exists; pass force=True to overwrite"
        )

    fantasm_toml_filepath.write_text(render_fantasm_toml(config))

    versions_dirpath = root_dirpath / config.versions_dirname
    versions_dirpath.mkdir(parents=True, exist_ok=True)
    if not any(versions_dirpath.iterdir()):
        (versions_dirpath / ".gitkeep").touch()

    return fantasm_toml_filepath


def add_version(
    versions_dirpath: Path,
    version_id: str,
    prefix: str,
) -> Path:
    """Create a new version directory ``{prefix}-{version_id}/``.

    Creates ``rom/`` and ``output/`` subdirectories (each with a
    ``.gitkeep``). Returns the new version directory path. Raises
    ``FileExistsError`` if it already exists, ``ValueError`` for an
    invalid prefix.
    """
    if not VALID_PREFIX_RE.match(prefix):
        raise ValueError(f"invalid prefix {prefix!r}")
    if not version_id:
        raise ValueError("version_id is required")

    versions_dirpath = Path(versions_dirpath)
    versions_dirpath.mkdir(parents=True, exist_ok=True)

    version_dirpath = versions_dirpath / f"{prefix}-{version_id}"
    if version_dirpath.exists():
        raise FileExistsError(f"{version_dirpath} already exists")

    version_dirpath.mkdir()
    for subname in ("rom", "output"):
        subdirpath = version_dirpath / subname
        subdirpath.mkdir()
        (subdirpath / ".gitkeep").touch()

    return version_dirpath


def list_versions(
    versions_dirpath: Path,
    prefixes: Iterable[str],
) -> list[VersionInfo]:
    """List ROM version directories matching any of the configured prefixes.

    Only entries whose name is exactly ``{prefix}-{version_id}`` for
    one of the prefixes are reported. Sorted by directory name.
    """
    versions_dirpath = Path(versions_dirpath)
    if not versions_dirpath.is_dir():
        return []

    prefix_list = list(prefixes)
    result: list[VersionInfo] = []

    for entry in sorted(versions_dirpath.iterdir()):
        if not entry.is_dir():
            continue
        for prefix in prefix_list:
            marker = f"{prefix}-"
            if entry.name.startswith(marker) and len(entry.name) > len(marker):
                version_id = entry.name[len(marker):]
                result.append(
                    VersionInfo(
                        prefix=prefix, version_id=version_id, dirpath=entry
                    )
                )
                break

    return result


__all__ = [
    "CONFIG_FILENAME",
    "ProjectInitConfig",
    "VALID_PREFIX_RE",
    "VERSIONS_DIRNAME_DEFAULT",
    "VersionInfo",
    "add_version",
    "init_project",
    "list_versions",
    "render_fantasm_toml",
]
