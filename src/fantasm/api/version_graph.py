"""Version DAG and per-version memory-region resolution.

Loads ``[memory]`` and ``[[versions.entry]]`` from a project's
``fantasm.toml`` and exposes a graph object that path-finds between
versions and computes effective memory regions per version (project
defaults plus the per-version override, plus reloc destinations
auto-merged).

See ``docs/configuration.md`` for the full schema. Quick recap of the
relevant TOML:

.. code-block:: toml

    [memory]
    regions          = [{ start = 0x0016, end = 0x0076 }, ...]
    external_regions = [{ start = 0xFC00, end = 0xFFFF }, ...]

    [[versions.entry]]
    id           = "3.34"
    parents      = []
    reloc_blocks = [{ source = 0x9307, dest = 0x0016, length = 0x61 }, ...]

    [[versions.entry]]
    id           = "page7-variant"
    parents      = ["3.34B"]
    memory.regions = [...]   # complete replacement of project regions
    reloc_blocks = [...]
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fantasm.config import ProjectContext


# --- Errors --------------------------------------------------------


class VersionGraphError(LookupError):
    """Base class for version-graph errors."""


class VersionNotInGraphError(VersionGraphError):
    """Raised when a referenced version isn't declared in the graph."""


class NoPathError(VersionGraphError):
    """Raised when no path exists between two versions."""

    def __init__(self, source_id: str, target_id: str) -> None:
        self.source_id = source_id
        self.target_id = target_id
        super().__init__(
            f"no path from {source_id!r} to {target_id!r} in the version graph"
        )


class VersionGraphCycleError(VersionGraphError):
    """Raised when the parents declarations imply a cycle."""


# --- Value types ---------------------------------------------------


@dataclass(frozen=True)
class Region:
    """An inclusive ``[start, end]`` address range."""

    start: int
    end: int

    def contains(self, address: int) -> bool:
        return self.start <= address <= self.end


@dataclass(frozen=True)
class RelocBlock:
    """A ``move()``-style relocation: source bytes → runtime destination."""

    source: int
    dest: int
    length: int

    @property
    def dest_region(self) -> Region:
        return Region(start=self.dest, end=self.dest + self.length - 1)


@dataclass(frozen=True)
class Version:
    """A node in the version graph.

    ``explicit_regions`` is ``None`` if the entry didn't override
    ``memory.regions`` (in which case the graph's project defaults
    apply).

    Free-form metadata fields (``notes``, ``description``,
    ``release_date``, ``source``) are surfaced for tooling and
    documentation but don't affect any analysis. ``release_date`` is
    expected to be an ISO-8601 date string but isn't parsed.
    """

    id: str
    parents: tuple[str, ...]
    reloc_blocks: tuple[RelocBlock, ...]
    explicit_regions: tuple[Region, ...] | None
    notes: str | None = None
    description: str | None = None
    release_date: str | None = None
    source: str | None = None


@dataclass(frozen=True)
class Edge:
    """An edge in the version DAG.

    ``parent_id`` is always the older endpoint, ``child_id`` always
    the newer. ``walked_forward`` is ``True`` when a path traverses
    the edge in the canonical direction (parent → child) and
    ``False`` when traversing it backwards (child → parent), which
    callers like ``backfill`` use to decide whether to invert the
    per-hop confidence map.
    """

    parent_id: str
    child_id: str
    walked_forward: bool


# --- Graph ---------------------------------------------------------


class VersionGraph:
    """A version DAG with per-version effective-region resolution."""

    def __init__(
        self,
        versions: Iterable[Version],
        project_regions: Iterable[Region] = (),
        project_external_regions: Iterable[Region] = (),
    ) -> None:
        self._versions: dict[str, Version] = {}
        for version in versions:
            if version.id in self._versions:
                raise VersionGraphError(
                    f"duplicate version id {version.id!r}"
                )
            self._versions[version.id] = version
        self._project_regions: tuple[Region, ...] = tuple(project_regions)
        self._project_external_regions: tuple[Region, ...] = tuple(
            project_external_regions
        )

        for version in self._versions.values():
            for parent_id in version.parents:
                if parent_id not in self._versions:
                    raise VersionGraphError(
                        f"version {version.id!r} declares parent "
                        f"{parent_id!r} which is not defined"
                    )

        # Cycle check via DFS on the parent relation.
        self._check_acyclic()

    # -- Container-ish protocol ------------------------------------

    def __contains__(self, version_id: object) -> bool:
        return version_id in self._versions

    def __len__(self) -> int:
        return len(self._versions)

    def ids(self) -> tuple[str, ...]:
        """Return all version ids in declaration order."""
        return tuple(self._versions)

    def get(self, version_id: str) -> Version:
        """Return the :class:`Version` for ``version_id``."""
        if version_id not in self._versions:
            raise VersionNotInGraphError(
                f"version {version_id!r} is not in the version graph"
            )
        return self._versions[version_id]

    # -- Path finding ----------------------------------------------

    def find_path(self, source_id: str, target_id: str) -> list[Edge]:
        """Return the shortest path of edges from ``source_id`` to ``target_id``.

        Walks the **undirected** projection of the DAG (each edge can
        be traversed in either direction). Same-source same-target
        returns an empty list. Raises :class:`VersionNotInGraphError`
        for unknown endpoints and :class:`NoPathError` when the
        endpoints are in disconnected components.
        """
        if source_id not in self._versions:
            raise VersionNotInGraphError(
                f"source {source_id!r} is not in the version graph"
            )
        if target_id not in self._versions:
            raise VersionNotInGraphError(
                f"target {target_id!r} is not in the version graph"
            )
        if source_id == target_id:
            return []

        adjacency = self._build_adjacency()

        # BFS shortest-path with parent-pointer reconstruction.
        came_from: dict[str, tuple[str, Edge] | None] = {source_id: None}
        queue: deque[str] = deque([source_id])
        while queue:
            current = queue.popleft()
            if current == target_id:
                break
            # Sorted neighbour traversal makes ties deterministic.
            for neighbour, edge in sorted(
                adjacency[current], key=lambda pair: pair[0]
            ):
                if neighbour in came_from:
                    continue
                came_from[neighbour] = (current, edge)
                queue.append(neighbour)

        if target_id not in came_from:
            raise NoPathError(source_id, target_id)

        path: list[Edge] = []
        node = target_id
        while came_from[node] is not None:
            previous, edge = came_from[node]  # type: ignore[misc]
            path.append(edge)
            node = previous
        path.reverse()
        return path

    # -- Region resolution -----------------------------------------

    def effective_regions(self, version_id: str) -> list[Region]:
        """Effective non-ROM regions for ``version_id``.

        The version's explicit ``memory.regions`` override (if set)
        otherwise the project default, plus reloc-block destinations
        from this version's ``reloc_blocks``. Overlapping or adjacent
        regions are merged; the result is sorted by start address.
        """
        version = self.get(version_id)
        base = (
            version.explicit_regions
            if version.explicit_regions is not None
            else self._project_regions
        )
        with_reloc = list(base) + [block.dest_region for block in version.reloc_blocks]
        return _normalise_regions(with_reloc)

    def effective_external_regions(self, version_id: str) -> list[Region]:
        """Effective hardware-mapped regions for ``version_id``.

        Project-level only — there's no per-version override (the
        BBC's hardware memory map is invariant within a project).
        Validates that ``version_id`` exists in the graph.
        """
        self.get(version_id)
        return _normalise_regions(self._project_external_regions)

    def reloc_pairs_for_edge(
        self, edge: Edge
    ) -> list[tuple[int, int, int, int]]:
        """Derive ``(src_parent, src_child, dest, length)`` tuples for ``edge``.

        Reloc blocks are matched across the edge's two endpoints by
        ``(dest, length)``. When either side has multiple blocks with
        the same key (rare), they are paired off positionally in the
        order they appear in each version's ``reloc_blocks`` list.
        Blocks that exist on only one side are silently dropped — a
        block whose ``dest``/``length`` differs across versions can't
        contribute to opcode matching anyway.

        Tuples are returned sorted by parent source address for
        determinism. The order ``(src_parent, src_child, dest,
        length)`` is independent of the edge's traversal direction;
        callers walking ``child -> parent`` swap or invert the
        resulting hop map themselves.
        """
        parent = self.get(edge.parent_id)
        child = self.get(edge.child_id)

        by_key_parent: dict[tuple[int, int], list[RelocBlock]] = {}
        for block in parent.reloc_blocks:
            by_key_parent.setdefault((block.dest, block.length), []).append(block)
        by_key_child: dict[tuple[int, int], list[RelocBlock]] = {}
        for block in child.reloc_blocks:
            by_key_child.setdefault((block.dest, block.length), []).append(block)

        result: list[tuple[int, int, int, int]] = []
        for key, parent_blocks in by_key_parent.items():
            child_blocks = by_key_child.get(key, [])
            for parent_block, child_block in zip(parent_blocks, child_blocks):
                result.append(
                    (
                        parent_block.source,
                        child_block.source,
                        key[0],
                        key[1],
                    )
                )

        result.sort(key=lambda t: t[0])
        return result

    # -- Private ---------------------------------------------------

    def _build_adjacency(
        self,
    ) -> dict[str, list[tuple[str, Edge]]]:
        adjacency: dict[str, list[tuple[str, Edge]]] = {
            v_id: [] for v_id in self._versions
        }
        for child_id, version in self._versions.items():
            for parent_id in version.parents:
                forward_edge = Edge(
                    parent_id=parent_id,
                    child_id=child_id,
                    walked_forward=True,
                )
                backward_edge = Edge(
                    parent_id=parent_id,
                    child_id=child_id,
                    walked_forward=False,
                )
                adjacency[parent_id].append((child_id, forward_edge))
                adjacency[child_id].append((parent_id, backward_edge))
        return adjacency

    def _check_acyclic(self) -> None:
        # DFS up the parent relation; any back-edge is a cycle.
        WHITE, GREY, BLACK = 0, 1, 2
        colour: dict[str, int] = {v_id: WHITE for v_id in self._versions}

        def visit(node: str, stack: list[str]) -> None:
            colour[node] = GREY
            stack.append(node)
            for parent_id in self._versions[node].parents:
                if colour[parent_id] == GREY:
                    cycle = stack[stack.index(parent_id):] + [parent_id]
                    raise VersionGraphCycleError(
                        f"cycle in parents: {' -> '.join(cycle)}"
                    )
                if colour[parent_id] == WHITE:
                    visit(parent_id, stack)
            stack.pop()
            colour[node] = BLACK

        for v_id in self._versions:
            if colour[v_id] == WHITE:
                visit(v_id, [])


# --- Helpers -------------------------------------------------------


def _normalise_regions(regions: Iterable[Region]) -> list[Region]:
    """Sort by start, merging overlapping or adjacent regions."""
    ordered = sorted(regions, key=lambda r: (r.start, r.end))
    if not ordered:
        return []
    merged: list[Region] = [ordered[0]]
    for region in ordered[1:]:
        last = merged[-1]
        if region.start <= last.end + 1:
            merged[-1] = Region(
                start=last.start, end=max(last.end, region.end)
            )
        else:
            merged.append(region)
    return merged


# --- TOML parsing --------------------------------------------------


def _parse_region(data: Mapping) -> Region:
    return Region(start=int(data["start"]), end=int(data["end"]))


def _parse_reloc_block(data: Mapping) -> RelocBlock:
    return RelocBlock(
        source=int(data["source"]),
        dest=int(data["dest"]),
        length=int(data["length"]),
    )


def _parse_version_entry(entry: Mapping) -> Version:
    if "id" not in entry:
        raise VersionGraphError(
            "version entry is missing required 'id' field"
        )
    explicit_regions: tuple[Region, ...] | None = None
    memory = entry.get("memory")
    if isinstance(memory, Mapping):
        regions = memory.get("regions")
        if regions is not None:
            explicit_regions = tuple(_parse_region(r) for r in regions)
    return Version(
        id=str(entry["id"]),
        parents=tuple(str(p) for p in entry.get("parents", [])),
        reloc_blocks=tuple(
            _parse_reloc_block(b) for b in entry.get("reloc_blocks", [])
        ),
        explicit_regions=explicit_regions,
        notes=entry.get("notes"),
        description=entry.get("description"),
        release_date=entry.get("release_date"),
        source=entry.get("source"),
    )


def load_version_graph(project_context: "ProjectContext") -> VersionGraph:
    """Build a :class:`VersionGraph` from ``project_context.config``.

    Reads ``[memory]`` and ``[[versions.entry]]``. Returns an empty
    graph (no versions, empty regions) when the config lacks either
    section — this is the right behaviour for a project that doesn't
    use the version-DAG features.

    Raises :class:`RuntimeError` if the project root isn't resolved.
    """
    if not project_context.has_root:
        raise RuntimeError(
            "Project root is not resolved; pass --project-root, set "
            "FANTASM_PROJECT_ROOT, or run from inside a fantasm project."
        )

    config = project_context.config
    memory_section = config.get("memory", {}) if isinstance(
        config.get("memory", {}), Mapping
    ) else {}
    project_regions = tuple(
        _parse_region(r) for r in memory_section.get("regions", [])
    )
    project_external_regions = tuple(
        _parse_region(r) for r in memory_section.get("external_regions", [])
    )

    versions_section = config.get("versions", {})
    entries = (
        versions_section.get("entry", [])
        if isinstance(versions_section, Mapping)
        else []
    )
    versions = [_parse_version_entry(e) for e in entries]

    return VersionGraph(
        versions=versions,
        project_regions=project_regions,
        project_external_regions=project_external_regions,
    )


__all__ = [
    "Edge",
    "NoPathError",
    "Region",
    "RelocBlock",
    "Version",
    "VersionGraph",
    "VersionGraphCycleError",
    "VersionGraphError",
    "VersionNotInGraphError",
    "load_version_graph",
]
