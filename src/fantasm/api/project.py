"""Project scaffolding.

Helpers to initialise a new fantasm project and to add or list its
targets. Two layouts are supported:

- **versions** (the default) — write ``fantasm.toml`` and create the
  standard ``versions/`` directory, one ``{prefix}-{id}/`` directory
  per version;
- **explicit** — adopt an existing project as it stands: write
  ``fantasm.toml`` with a ``[[targets]]`` entry naming the files where
  they already are, and create nothing else.

Pure helpers; the ``fantasm project`` Click sub-commands wrap these.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .inf import InfParseError, read_inf, sidecar_inf_filepath


CONFIG_FILENAME = "fantasm.toml"
VERSIONS_DIRNAME_DEFAULT = "versions"
VALID_PREFIX_RE = re.compile(r"^[A-Za-z0-9_-]+$")
VALID_TARGET_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
PROJECT_LAYOUTS = ("versions", "explicit")


@dataclass(frozen=True)
class TargetSpec:
    """A ``[[targets]]`` entry to write into ``fantasm.toml``.

    Paths are as they should appear in the file: relative to the
    project root (or absolute). ``inf_source`` names the ``.inf`` file
    the addresses were read from, recorded as a comment.
    """

    id: str
    binary: str
    driver: str
    asm: str
    json: str
    load_address: int | None = None
    exec_address: int | None = None
    metadata: str | None = None
    inf_source: str | None = None

    def __post_init__(self) -> None:
        if not VALID_TARGET_ID_RE.match(self.id):
            raise ValueError(
                f"invalid target id {self.id!r} (letters, digits, '.', "
                "'_' and '-' only)"
            )
        for name in ("load_address", "exec_address"):
            value = getattr(self, name)
            if value is not None and not 0 <= value <= 0xFFFF:
                raise ValueError(f"{name} {value:#x} is outside &0000-&FFFF")


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
    layout: str = "versions"
    targets: tuple[TargetSpec, ...] = field(default=())

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("project name is required")
        if self.layout not in PROJECT_LAYOUTS:
            raise ValueError(
                f"unknown layout {self.layout!r}; choose from "
                f"{', '.join(PROJECT_LAYOUTS)}"
            )
        if self.layout == "explicit" and not self.targets:
            raise ValueError("the explicit layout needs at least one target")
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
    """A discovered version directory."""

    prefix: str
    version_id: str
    dirpath: Path


def _toml_string(value: str) -> str:
    """A TOML basic string (JSON string escapes are valid TOML)."""
    return json.dumps(value, ensure_ascii=False)


def render_target_entry(spec: TargetSpec) -> str:
    """Render one ``[[targets]]`` block (ending in a newline)."""
    lines = [
        "[[targets]]",
        f"id = {_toml_string(spec.id)}",
        f"binary = {_toml_string(spec.binary)}",
    ]
    note = f"  # from {spec.inf_source}" if spec.inf_source else ""
    if spec.load_address is not None:
        lines.append(f"load_address = 0x{spec.load_address:04X}{note}")
    if spec.exec_address is not None:
        lines.append(f"exec_address = 0x{spec.exec_address:04X}{note}")
    lines += [
        f"driver = {_toml_string(spec.driver)}",
        f"asm = {_toml_string(spec.asm)}",
        f"json = {_toml_string(spec.json)}",
    ]
    if spec.metadata is not None:
        lines.append(f"metadata = {_toml_string(spec.metadata)}")
    return "\n".join(lines) + "\n"


def render_fantasm_toml(config: ProjectInitConfig) -> str:
    """Render the ``fantasm.toml`` content for a new project.

    Output is hand-formatted (with comments) rather than serialised by
    a TOML library, so the file is still readable when a human edits
    it later.
    """
    prefix_literal = ", ".join(_toml_string(p) for p in config.prefixes)
    lines = [
        "# fantasm project configuration. See docs/configuration.md for the schema.",
        "",
        "[project]",
        f"name = {_toml_string(config.name)}",
        "",
        "[binary]",
        '# Default CPU for opcode decoding: "6502" (NMOS) or "65c02" (CMOS).',
        f"cpu = {_toml_string(config.cpu)}",
        "",
    ]
    if config.layout == "versions":
        lines.append("[versions]")
        if config.versions_dirname != VERSIONS_DIRNAME_DEFAULT:
            lines.append(f"directory = {_toml_string(config.versions_dirname)}")
        lines.append(f"prefixes = [{prefix_literal}]")
        lines.append("")
    for spec in config.targets:
        lines.append(render_target_entry(spec))
    return "\n".join(lines)


def init_project(
    root_dirpath: Path,
    config: ProjectInitConfig,
    *,
    force: bool = False,
) -> Path:
    """Initialise a fantasm project at ``root_dirpath``.

    Writes ``fantasm.toml``. For the ``versions`` layout, also ensures
    the versions directory exists (creating it with a ``.gitkeep`` if
    it didn't); the ``explicit`` layout creates nothing else. Returns
    the ``fantasm.toml`` path.

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
    if config.layout == "explicit":
        return fantasm_toml_filepath

    versions_dirpath = root_dirpath / config.versions_dirname
    versions_dirpath.mkdir(parents=True, exist_ok=True)
    if not any(versions_dirpath.iterdir()):
        (versions_dirpath / ".gitkeep").touch()

    return fantasm_toml_filepath


def add_version(
    versions_dirpath: Path,
    version_id: str,
    prefix: str,
    binary_dirname: str = "rom",
) -> Path:
    """Create a new version directory ``{prefix}-{version_id}/``.

    Creates the binary subdirectory (``binary_dirname``, default
    ``rom/`` per the historical ROM convention) and ``output/`` (each
    with a ``.gitkeep``). Returns the new version directory path.
    Raises ``FileExistsError`` if it already exists, ``ValueError``
    for an invalid prefix.
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
    for subname in (binary_dirname, "output"):
        subdirpath = version_dirpath / subname
        subdirpath.mkdir()
        (subdirpath / ".gitkeep").touch()

    return version_dirpath


def append_target(fantasm_toml_filepath: Path, spec: TargetSpec) -> None:
    """Append a ``[[targets]]`` entry to an existing ``fantasm.toml``.

    Raises ``ValueError`` if a target with the same id is already
    declared, or if the result would not parse (for example because
    the file declares ``targets`` as an inline array); the file is
    left unchanged in that case.
    """
    fantasm_toml_filepath = Path(fantasm_toml_filepath)
    original = fantasm_toml_filepath.read_text()
    existing = tomllib.loads(original).get("targets", [])
    if any(
        isinstance(entry, dict) and entry.get("id") == spec.id
        for entry in existing
    ):
        raise ValueError(f"target {spec.id!r} is already declared")
    separator = "" if original.endswith("\n\n") or not original else (
        "\n" if original.endswith("\n") else "\n\n"
    )
    updated = original + separator + render_target_entry(spec)
    try:
        tomllib.loads(updated)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(
            f"can't append a [[targets]] entry to {fantasm_toml_filepath}: "
            f"{exc}"
        ) from exc
    fantasm_toml_filepath.write_text(updated)


def parse_binary_option(text: str) -> tuple[str, int | None]:
    """Split a ``PATH[@ADDR]`` option value.

    ``ADDR`` is hexadecimal, with an optional ``&``, ``$`` or ``0x``
    prefix. A trailing ``@...`` that isn't an address is left as part
    of the path. Raises ``ValueError`` for an address above ``&FFFF``.
    """
    path, at, address_text = text.rpartition("@")
    if not at:
        return text, None
    match = re.fullmatch(r"(?:&|\$|0[xX])?([0-9A-Fa-f]+)", address_text)
    if match is None or not path:
        return text, None
    address = int(match.group(1), 16)
    if address > 0xFFFF:
        raise ValueError(f"load address &{address:X} is above &FFFF")
    return path, address


def binary_addresses(
    binary_filepath: Path, load_address: int | None = None
) -> tuple[int, int | None, Path | None]:
    """Return ``(load, exec, inf_filepath)`` for a binary.

    With ``load_address`` given, returns it (and no exec address or
    ``.inf``). Otherwise reads the binary's ``.inf`` sidecar. Raises
    :class:`~fantasm.api.inf.InfParseError`, with a hint to give the
    address explicitly, when there's no sidecar or it can't be parsed.
    """
    if load_address is not None:
        return load_address, None, None
    inf_filepath = sidecar_inf_filepath(binary_filepath)
    if inf_filepath is None:
        raise InfParseError(
            f"no load address given for {binary_filepath} and no .inf "
            "sidecar found; give one as PATH@ADDR (e.g. "
            f"{binary_filepath.name}@1900)"
        )
    try:
        record = read_inf(inf_filepath)
        return record.load_address_16(), record.exec_address_16(), inf_filepath
    except InfParseError as exc:
        raise InfParseError(
            f"{exc}; give the load address explicitly as PATH@ADDR"
        ) from exc


def project_relative(path: Path, root_dirpath: Path) -> str:
    """``path`` relative to ``root_dirpath`` (POSIX form) when inside it,
    else absolute."""
    absolute = Path(path).resolve()
    root = Path(root_dirpath).resolve()
    try:
        return absolute.relative_to(root).as_posix()
    except ValueError:
        return str(absolute)


def default_target_paths(target_id: str) -> dict[str, str]:
    """Default driver / asm / json paths for a new explicit target."""
    stem = target_id.replace(".", "_")
    return {
        "driver": f"disasm_{stem}.py",
        "asm": f"output/{target_id}.asm",
        "json": f"output/{target_id}.json",
    }


def list_versions(
    versions_dirpath: Path,
    prefixes: Iterable[str],
) -> list[VersionInfo]:
    """List version directories matching any of the configured prefixes.

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
    "PROJECT_LAYOUTS",
    "ProjectInitConfig",
    "TargetSpec",
    "VALID_PREFIX_RE",
    "VALID_TARGET_ID_RE",
    "VERSIONS_DIRNAME_DEFAULT",
    "VersionInfo",
    "add_version",
    "append_target",
    "binary_addresses",
    "default_target_paths",
    "init_project",
    "list_versions",
    "parse_binary_option",
    "project_relative",
    "render_fantasm_toml",
    "render_target_entry",
]
