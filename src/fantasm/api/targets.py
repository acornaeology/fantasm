"""Disassembly targets and where their files live.

A **target** is one thing being disassembled: a program binary loaded
at some address, the driver script that disassembles it, and the
``.asm`` / ``.json`` artefacts the driver writes. Every per-version
command operates on a target; in a multi-version project each version
is a target.

Where a target's files live is resolved in three layers, each one
overriding the one before it key by key:

1. **Convention** — the ``versions/<prefix>-<id>/`` tree, configured
   by ``[versions]`` and ``[binary]``. This is the default, and the
   only layer a project without ``[layout]`` or ``[[targets]]`` uses.
2. **``[layout]`` templates** — path templates rendered per target id,
   for multi-version projects whose files don't follow the
   ``versions/`` convention::

       [layout]
       binary = "roms/{id}.rom"
       driver = "scripts/dis_{id_no_dots}.py"
       asm    = "build/{id}.asm"
       json   = "build/{id}.json"

3. **``[[targets]]`` entries** — explicit per-target paths, for
   adopting a project with its own layout as it stands::

       [[targets]]
       id     = "loader"
       binary = "orig/ELITE"        # load/exec from orig/ELITE.inf
       driver = "tools/dis_loader.py"
       asm    = "build/loader.asm"
       json   = "build/loader.json"

All configured paths are relative to the project root. A target's
load address comes from, in order: its ``load_address``, its ``.inf``
sidecar (for ``[[targets]]`` entries, read automatically when present
or named by ``inf``), the ``[layout]`` ``load_address``, and finally
``[binary] base_address``.

The set of known targets is the ``[[targets]]`` ids, then (when
``[layout]`` is configured) the ``[[versions.entry]]`` ids and any ids
discovered by ``[layout] discover``, then the version directories on
disk. With exactly one target — or a ``[project] default_target`` —
commands can be run without naming it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .inf import InfParseError, read_inf, sidecar_inf_filepath
from .paths import (
    VersionNotFoundError,
    project_binary_base,
    project_binary_dirname,
    project_binary_extension,
    project_binary_filename_template,
    project_binary_metadata_filename,
    project_driver_dirname,
    project_driver_filename_template,
    project_rom_prefixes,
    project_versions_dirpath,
    render_binary_filename,
    render_driver_filename,
    resolve_version_dirpath,
)

if TYPE_CHECKING:
    from fantasm.config import ProjectContext


TARGET_SOURCES = ("convention", "layout", "explicit")

# Keys that name a file, resolvable by every layer.
PATH_KEYS = ("binary", "driver", "asm", "json", "metadata")

TARGET_KEYS = frozenset({
    "id", "prefix", "binary", "images", "driver", "asm", "json",
    "metadata", "load_address", "exec_address", "inf", "driver_cwd",
    "verify", "description",
})
IMAGE_KEYS = frozenset({
    "name", "path", "load_address", "exec_address", "inf",
})
LAYOUT_KEYS = frozenset({
    "binary", "driver", "asm", "json", "metadata", "load_address",
    "exec_address", "inf", "driver_cwd", "discover",
})


class TargetConfigError(ValueError):
    """``[layout]`` or ``[[targets]]`` configuration is invalid, or a
    target's files can't be resolved from it."""


class TargetNotFoundError(LookupError):
    """No configured target has the requested id."""

    def __init__(self, target_id: str, available: Sequence[str]) -> None:
        self.target_id = target_id
        self.available: tuple[str, ...] = tuple(available)
        listing = ", ".join(self.available) if self.available else "(none)"
        super().__init__(
            f"target {target_id!r} not found; available: {listing}"
        )


@dataclass(frozen=True)
class TargetFiles:
    """The resolved files and load address of one target.

    ``version_id`` is the target id (the name is kept from when every
    target was a version). ``version_dirpath`` is the target's version
    directory under the convention, or the project root for a target
    configured wholly by ``[layout]`` / ``[[targets]]``; relative
    ``docs`` paths in the metadata file resolve against it.
    ``metadata_filepath`` is ``None`` when no metadata file is
    configured. ``load_address`` is ``None`` only on instances built
    by hand.
    """

    version_id: str
    prefix: str
    version_dirpath: Path
    binary_filepath: Path
    metadata_filepath: Path | None
    asm_filepath: Path
    json_filepath: Path
    driver_filepath: Path
    load_address: int | None = None
    exec_address: int | None = None
    source: str = "convention"
    image_name: str | None = None
    inf_filepath: Path | None = None
    driver_cwd_dirpath: Path | None = None

    @property
    def target_id(self) -> str:
        return self.version_id


# --- Config readers --------------------------------------------------


def _project_root(project: ProjectContext) -> Path:
    if not project.has_root or project.root_dirpath is None:
        raise RuntimeError(
            "Project root is not resolved; pass --project-root, set "
            "FANTASM_PROJECT_ROOT, or run from inside a directory tree "
            "containing fantasm.toml."
        )
    return project.root_dirpath


def project_layout(project: ProjectContext) -> Mapping[str, Any]:
    """Return the validated ``[layout]`` section (empty when absent)."""
    layout = project.config.get("layout", {})
    if not isinstance(layout, Mapping):
        raise TargetConfigError("[layout] must be a table")
    unknown = set(layout) - LAYOUT_KEYS
    if unknown:
        raise TargetConfigError(
            f"[layout] has unknown key(s): {', '.join(sorted(unknown))}; "
            f"recognised keys are {', '.join(sorted(LAYOUT_KEYS))}"
        )
    return layout


def project_target_entries(
    project: ProjectContext,
) -> list[Mapping[str, Any]]:
    """Return the validated ``[[targets]]`` entries, in config order."""
    entries = project.config.get("targets", [])
    if not isinstance(entries, list):
        raise TargetConfigError("targets must be an array of tables")
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            raise TargetConfigError(f"[[targets]] #{index + 1} is not a table")
        target_id = entry.get("id")
        if not isinstance(target_id, str) or not target_id:
            raise TargetConfigError(
                f"[[targets]] #{index + 1} needs a non-empty string id"
            )
        if target_id in seen:
            raise TargetConfigError(f"duplicate [[targets]] id {target_id!r}")
        seen.add(target_id)
        unknown = set(entry) - TARGET_KEYS
        if unknown:
            raise TargetConfigError(
                f"[[targets]] {target_id!r} has unknown key(s): "
                f"{', '.join(sorted(unknown))}; recognised keys are "
                f"{', '.join(sorted(TARGET_KEYS))}"
            )
    return entries


def _target_entry(
    project: ProjectContext, target_id: str
) -> Mapping[str, Any] | None:
    for entry in project_target_entries(project):
        if entry["id"] == target_id:
            return entry
    return None


def uses_target_config(project: ProjectContext) -> bool:
    """``True`` when ``[layout]`` or ``[[targets]]`` is configured."""
    return "layout" in project.config or "targets" in project.config


# --- Template rendering ----------------------------------------------


def target_tokens(target_id: str, prefix: str) -> dict[str, str]:
    """Token substitutions for ``[layout]`` templates.

    ``{id}``, ``{id_no_dots}``, ``{id_upper}``, ``{id_lower}``, the
    ``{prefix}`` family and the ``{version_id}`` family (aliases of
    the ``{id}`` ones, matching ``[versions] driver_filename``).
    """
    no_dots = target_id.replace(".", "")
    return {
        "id": target_id,
        "id_no_dots": no_dots,
        "id_upper": target_id.upper(),
        "id_lower": target_id.lower(),
        "version_id": target_id,
        "version_id_no_dots": no_dots,
        "version_id_upper": target_id.upper(),
        "version_id_lower": target_id.lower(),
        "prefix": prefix,
        "prefix_upper": prefix.upper(),
        "prefix_lower": prefix.lower(),
    }


def render_layout_template(
    template: str, target_id: str, prefix: str, *, key: str = "path"
) -> str:
    """Render a ``[layout]`` template. Raises :class:`TargetConfigError`."""
    if not isinstance(template, str):
        raise TargetConfigError(f"[layout] {key} must be a string")
    try:
        return template.format(**target_tokens(target_id, prefix))
    except (KeyError, IndexError, ValueError) as exc:
        raise TargetConfigError(
            f"[layout] {key} = {template!r}: unknown or malformed token "
            f"({exc}); recognised tokens are "
            + ", ".join(f"{{{t}}}" for t in target_tokens("", ""))
        ) from exc


_TOKEN_RE = re.compile(r"\{([^{}]*)\}")


def discover_target_ids(project: ProjectContext) -> list[str]:
    """Ids found on disk by the ``[layout] discover`` template.

    The template is a path relative to the project root containing
    exactly one ``{id}`` token, for example ``"roms/{id}.rom"``; every
    matching file or directory contributes its ``{id}`` part. Returns
    ``[]`` when ``discover`` isn't set.
    """
    template = project_layout(project).get("discover")
    if template is None:
        return []
    if not isinstance(template, str):
        raise TargetConfigError("[layout] discover must be a string")
    tokens = _TOKEN_RE.findall(template)
    if tokens != ["id"]:
        raise TargetConfigError(
            f"[layout] discover = {template!r} must contain exactly one "
            "{id} token and no others"
        )
    root_dirpath = _project_root(project)
    head, _, tail = template.partition("{id}")
    pattern = re.compile(
        "^" + re.escape(head) + "(?P<id>[^/]+?)" + re.escape(tail) + "$"
    )
    found: set[str] = set()
    for candidate in root_dirpath.glob(template.replace("{id}", "*")):
        relative = candidate.relative_to(root_dirpath).as_posix()
        match = pattern.match(relative)
        if match:
            found.add(match.group("id"))
    return sorted(found)


# --- Target listing ----------------------------------------------------


def _convention_target_ids(project: ProjectContext) -> list[str]:
    # Imported here: project.py has no dependency on targets, but this
    # keeps the module import graph acyclic should that change.
    from .project import list_versions

    prefixes = project_rom_prefixes(project)
    if not prefixes:
        return []
    return [
        info.version_id
        for info in list_versions(project_versions_dirpath(project), prefixes)
    ]


def list_target_ids(project: ProjectContext) -> list[str]:
    """Return every known target id, without duplicates.

    Order: ``[[targets]]`` ids in config order; then, when ``[layout]``
    is configured, the ``[[versions.entry]]`` ids and the ids found by
    ``[layout] discover``; then the version directories on disk.
    """
    ids: list[str] = [entry["id"] for entry in project_target_entries(project)]
    if "layout" in project.config:
        project_layout(project)
        entries = project.config.get("versions", {}).get("entry", [])
        ids += [e["id"] for e in entries if isinstance(e, Mapping) and "id" in e]
        ids += discover_target_ids(project)
    ids += _convention_target_ids(project)
    return list(dict.fromkeys(ids))


def default_target_id(project: ProjectContext) -> str | None:
    """The target commands use when none is named, or ``None``.

    ``[project] default_target`` when set (it must name a known
    target), else the only target when there is exactly one.
    """
    ids = list_target_ids(project)
    configured = project.config.get("project", {}).get("default_target")
    if configured is not None:
        if configured not in ids:
            raise TargetConfigError(
                f"[project] default_target = {configured!r} is not a known "
                f"target; available: {', '.join(ids) or '(none)'}"
            )
        return configured
    if len(ids) == 1:
        return ids[0]
    return None


# --- Resolution ----------------------------------------------------------


def _parse_address(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise TargetConfigError(f"{where} must be an integer or hex string")
    if isinstance(value, str):
        text = value.strip()
        for marker in ("&", "$", "0x", "0X"):
            if text.startswith(marker):
                text = text[len(marker):]
                break
        try:
            value = int(text, 16)
        except ValueError as exc:
            raise TargetConfigError(
                f"{where} = {value!r} is not a hexadecimal address"
            ) from exc
    if not 0 <= value <= 0xFFFF:
        raise TargetConfigError(f"{where} = {value:#x} is outside &0000-&FFFF")
    return value


def _single_image(
    entry: Mapping[str, Any], target_id: str
) -> Mapping[str, Any]:
    """Fold an ``images`` list (at most one image) into target keys."""
    images = entry.get("images")
    if images is None:
        return entry
    if "binary" in entry:
        raise TargetConfigError(
            f"[[targets]] {target_id!r}: give either binary or images, not both"
        )
    if not isinstance(images, list) or not images:
        raise TargetConfigError(
            f"[[targets]] {target_id!r}: images must be a non-empty list"
        )
    if len(images) > 1:
        raise TargetConfigError(
            f"[[targets]] {target_id!r}: targets with more than one image "
            "are not supported yet; declare one target per file"
        )
    image = images[0]
    if not isinstance(image, Mapping) or "path" not in image:
        raise TargetConfigError(
            f"[[targets]] {target_id!r}: each image needs a path"
        )
    unknown = set(image) - IMAGE_KEYS
    if unknown:
        raise TargetConfigError(
            f"[[targets]] {target_id!r} image has unknown key(s): "
            f"{', '.join(sorted(unknown))}"
        )
    merged = {k: v for k, v in entry.items() if k != "images"}
    for key in ("load_address", "exec_address", "inf"):
        if key in image:
            if key in entry:
                raise TargetConfigError(
                    f"[[targets]] {target_id!r}: {key} is given on both "
                    "the target and its image"
                )
            merged[key] = image[key]
    merged["binary"] = image["path"]
    if "name" in image:
        merged["image_name"] = image["name"]
    return merged


def _convention_files(
    project: ProjectContext, target_id: str
) -> dict[str, Any]:
    """Today's ``versions/<prefix>-<id>/`` derivation, as a dict.

    Raises :class:`VersionNotFoundError` when the version directory
    doesn't exist and :class:`TargetConfigError` when no prefixes are
    configured.
    """
    versions_dirpath = project_versions_dirpath(project)
    prefixes = project_rom_prefixes(project)
    if not prefixes:
        raise TargetConfigError(
            "no [versions] prefixes configured in fantasm.toml "
            "(and no [project] name to fall back on)"
        )
    version_dirpath = resolve_version_dirpath(
        versions_dirpath, target_id, prefixes
    )
    name = version_dirpath.name
    matched_prefix = next(
        (p for p in prefixes if name == p or name.startswith(f"{p}-")),
        prefixes[0],
    )
    base = f"{matched_prefix}-{target_id}"
    driver_filename = render_driver_filename(
        project_driver_filename_template(project), matched_prefix, target_id
    )
    extension = project_binary_extension(project)
    binary_suffix = f".{extension}" if extension else ""
    binary_dirpath = version_dirpath / project_binary_dirname(project)
    binary_basename = render_binary_filename(
        project_binary_filename_template(project), matched_prefix, target_id
    )
    return {
        "prefix": matched_prefix,
        "version_dirpath": version_dirpath,
        "binary": binary_dirpath / f"{binary_basename}{binary_suffix}",
        "metadata": (
            binary_dirpath / project_binary_metadata_filename(project)
        ),
        "asm": version_dirpath / "output" / f"{base}.asm",
        "json": version_dirpath / "output" / f"{base}.json",
        "driver": (
            version_dirpath
            / project_driver_dirname(project)
            / driver_filename
        ),
    }


def resolve_target(project: ProjectContext, target_id: str) -> TargetFiles:
    """Resolve a target's files and load address.

    Raises:

    - :class:`~fantasm.api.paths.VersionNotFoundError` for an unknown
      id in a project that uses only the ``versions/`` convention
      (exactly as before targets existed);
    - :class:`TargetNotFoundError` for an unknown id in a project with
      ``[layout]`` or ``[[targets]]``;
    - :class:`TargetConfigError` for invalid configuration, or a path
      no layer can supply;
    - :class:`~fantasm.api.inf.InfParseError` for an unreadable
      ``.inf`` sidecar.
    """
    if not uses_target_config(project):
        conv = _convention_files(project, target_id)
        return TargetFiles(
            version_id=target_id,
            prefix=conv["prefix"],
            version_dirpath=conv["version_dirpath"],
            binary_filepath=conv["binary"],
            metadata_filepath=conv["metadata"],
            asm_filepath=conv["asm"],
            json_filepath=conv["json"],
            driver_filepath=conv["driver"],
            load_address=project_binary_base(project),
            source="convention",
        )

    root_dirpath = _project_root(project)
    layout = project_layout(project)
    entry = _target_entry(project, target_id)
    if entry is None and target_id not in list_target_ids(project):
        raise TargetNotFoundError(target_id, list_target_ids(project))
    if entry is not None:
        entry = _single_image(entry, target_id)

    conv: dict[str, Any] | None = None
    conv_error: Exception | None = None
    try:
        conv = _convention_files(project, target_id)
    except (VersionNotFoundError, TargetConfigError) as exc:
        conv_error = exc

    prefixes = project_rom_prefixes(project)
    if entry is not None and "prefix" in entry:
        prefix = str(entry["prefix"])
    elif conv is not None:
        prefix = conv["prefix"]
    elif prefixes:
        prefix = prefixes[0]
    else:
        prefix = target_id

    def where(key: str) -> str:
        return f"[[targets]] {target_id!r} {key}"

    resolved: dict[str, Path | None] = {}
    sources: set[str] = set()
    for key in PATH_KEYS:
        if entry is not None and key in entry:
            if not isinstance(entry[key], str):
                raise TargetConfigError(f"{where(key)} must be a string path")
            resolved[key] = root_dirpath / entry[key]
            sources.add("explicit")
        elif key in layout:
            resolved[key] = root_dirpath / render_layout_template(
                layout[key], target_id, prefix, key=key
            )
            sources.add("layout")
        elif conv is not None:
            resolved[key] = conv[key]
            sources.add("convention")
        elif key == "metadata":
            resolved[key] = None
        else:
            detail = f" ({conv_error})" if conv_error is not None else ""
            raise TargetConfigError(
                f"target {target_id!r}: no {key} path configured — set "
                f"{key} in its [[targets]] entry or in [layout] — and no "
                f"version directory to fall back on{detail}"
            )

    if "explicit" in sources:
        source = "explicit"
    elif "layout" in sources:
        source = "layout"
    else:
        source = "convention"

    binary_filepath = resolved["binary"]
    assert binary_filepath is not None

    # Load / exec address and .inf sidecar.
    def setting(key: str) -> Any:
        if entry is not None and key in entry:
            return entry[key], where(key)
        if key in layout:
            return layout[key], f"[layout] {key}"
        return None, None

    inf_setting, inf_where = setting("inf")
    inf_filepath: Path | None = None
    if inf_setting is True:
        inf_filepath = sidecar_inf_filepath(binary_filepath)
        if inf_filepath is None:
            raise InfParseError(
                f"{inf_where} = true but no .inf sidecar was found beside "
                f"{binary_filepath}; give load_address explicitly instead"
            )
    elif isinstance(inf_setting, str):
        inf_filepath = root_dirpath / render_layout_template(
            inf_setting, target_id, prefix, key="inf"
        )
    elif inf_setting not in (None, False):
        raise TargetConfigError(f"{inf_where} must be true, false or a path")
    elif inf_setting is None and entry is not None:
        # Explicit targets pick up a sidecar automatically.
        inf_filepath = sidecar_inf_filepath(binary_filepath)

    load_value, load_where = setting("load_address")
    exec_value, exec_where = setting("exec_address")
    load_address: int | None = None
    exec_address: int | None = None
    if load_value is not None:
        load_address = _parse_address(load_value, load_where)
    if exec_value is not None:
        exec_address = _parse_address(exec_value, exec_where)
    # An automatically found sidecar is only consulted when the load
    # address is still unknown, so a malformed one can't break a target
    # whose addresses are configured explicitly.
    needs_inf = load_address is None or (
        exec_address is None and inf_setting is not None
    )
    if inf_filepath is not None and needs_inf:
        try:
            record = read_inf(inf_filepath)
            if load_address is None:
                load_address = record.load_address_16()
            if exec_address is None:
                exec_address = record.exec_address_16()
        except InfParseError as exc:
            raise InfParseError(
                f"{exc}. Give the address explicitly with load_address "
                f"(and exec_address) in target {target_id!r}'s "
                "[[targets]] entry in fantasm.toml"
            ) from exc
    if load_address is None:
        load_address = project_binary_base(project)

    driver_cwd_value, driver_cwd_where = setting("driver_cwd")
    driver_cwd_dirpath: Path | None = None
    if driver_cwd_value is not None:
        driver_cwd_dirpath = root_dirpath / render_layout_template(
            driver_cwd_value, target_id, prefix, key="driver_cwd"
        )

    asm_filepath = resolved["asm"]
    json_filepath = resolved["json"]
    driver_filepath = resolved["driver"]
    assert asm_filepath is not None
    assert json_filepath is not None
    assert driver_filepath is not None

    return TargetFiles(
        version_id=target_id,
        prefix=prefix,
        version_dirpath=(
            conv["version_dirpath"] if conv is not None else root_dirpath
        ),
        binary_filepath=binary_filepath,
        metadata_filepath=resolved["metadata"],
        asm_filepath=asm_filepath,
        json_filepath=json_filepath,
        driver_filepath=driver_filepath,
        load_address=load_address,
        exec_address=exec_address,
        source=source,
        image_name=(entry or {}).get("image_name"),
        inf_filepath=inf_filepath,
        driver_cwd_dirpath=driver_cwd_dirpath,
    )


def target_verify_settings(
    project: ProjectContext, target_id: str
) -> Mapping[str, Any]:
    """Return ``[verify]`` merged with the target's own ``verify`` table."""
    settings = dict(project.config.get("verify", {}))
    if "targets" in project.config:
        entry = _target_entry(project, target_id)
        if entry is not None and "verify" in entry:
            override = entry["verify"]
            if not isinstance(override, Mapping):
                raise TargetConfigError(
                    f"[[targets]] {target_id!r} verify must be a table"
                )
            settings.update(override)
    return settings


__all__ = [
    "IMAGE_KEYS",
    "LAYOUT_KEYS",
    "PATH_KEYS",
    "TARGET_KEYS",
    "TARGET_SOURCES",
    "TargetConfigError",
    "TargetFiles",
    "TargetNotFoundError",
    "default_target_id",
    "discover_target_ids",
    "list_target_ids",
    "project_layout",
    "project_target_entries",
    "render_layout_template",
    "resolve_target",
    "target_tokens",
    "target_verify_settings",
    "uses_target_config",
]
