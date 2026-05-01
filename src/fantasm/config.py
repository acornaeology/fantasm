"""Project-root discovery and ``fantasm.toml`` loading."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping


CONFIG_FILENAME = "fantasm.toml"


@dataclass(frozen=True)
class ProjectContext:
    """The resolved project context for a single fantasm invocation."""

    root_dirpath: Path | None
    config_filepath: Path | None = None
    config: Mapping[str, Any] = field(default_factory=dict)

    @property
    def has_root(self) -> bool:
        return self.root_dirpath is not None


def _walk_up_for_config(start_dirpath: Path) -> Path | None:
    for candidate_dirpath in [start_dirpath, *start_dirpath.parents]:
        if (candidate_dirpath / CONFIG_FILENAME).is_file():
            return candidate_dirpath
    return None


def resolve_project_context(explicit_root_dirpath: Path | None) -> ProjectContext:
    """Resolve the project root and load ``fantasm.toml`` if present.

    Resolution order:

    1. ``explicit_root_dirpath`` — populated by Click from ``--project-root`` or,
       failing that, the ``FANTASM_PROJECT_ROOT`` environment variable.
    2. Walk upwards from the current working directory looking for
       ``fantasm.toml``.
    3. Unresolved (returns a context with ``root_dirpath = None``).
    """
    if explicit_root_dirpath is not None:
        root_dirpath: Path | None = Path(explicit_root_dirpath).resolve()
    else:
        root_dirpath = _walk_up_for_config(Path.cwd().resolve())

    if root_dirpath is None:
        return ProjectContext(root_dirpath=None)

    config_filepath: Path | None = root_dirpath / CONFIG_FILENAME
    if config_filepath is not None and config_filepath.is_file():
        with config_filepath.open("rb") as config_file:
            config: Mapping[str, Any] = tomllib.load(config_file)
    else:
        config_filepath = None
        config = {}

    return ProjectContext(
        root_dirpath=root_dirpath,
        config_filepath=config_filepath,
        config=config,
    )
