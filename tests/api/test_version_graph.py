"""Tests for ``fantasm.api.version_graph``."""

from __future__ import annotations

import pytest

from fantasm.api.version_graph import (
    Edge,
    NoPathError,
    Region,
    RelocBlock,
    Version,
    VersionGraph,
    VersionGraphCycleError,
    VersionGraphError,
    VersionNotInGraphError,
    load_version_graph,
)
from fantasm.config import ProjectContext


# --- Region / RelocBlock ------------------------------------------


class TestRegion:
    def test_contains(self) -> None:
        r = Region(0x8000, 0x80FF)
        assert r.contains(0x8000) is True
        assert r.contains(0x80FF) is True  # end is inclusive
        assert r.contains(0x7FFF) is False
        assert r.contains(0x8100) is False


class TestRelocBlock:
    def test_dest_region(self) -> None:
        block = RelocBlock(source=0x9000, dest=0x0400, length=0x100)
        # length 0x100 starting at 0x0400 ends at 0x04FF (inclusive).
        assert block.dest_region == Region(start=0x0400, end=0x04FF)


# --- Construction & validation ------------------------------------


def _v(id: str, parents: tuple[str, ...] = (), reloc=()) -> Version:
    return Version(
        id=id, parents=parents, reloc_blocks=reloc, explicit_regions=None
    )


class TestConstruction:
    def test_simple(self) -> None:
        graph = VersionGraph(
            [_v("3.34"), _v("3.34B", parents=("3.34",))]
        )
        assert len(graph) == 2
        assert "3.34" in graph
        assert "3.34B" in graph

    def test_unknown_parent_rejected(self) -> None:
        with pytest.raises(VersionGraphError, match="declares parent"):
            VersionGraph([_v("3.34B", parents=("nonexistent",))])

    def test_duplicate_id_rejected(self) -> None:
        with pytest.raises(VersionGraphError, match="duplicate"):
            VersionGraph([_v("3.34"), _v("3.34")])

    def test_self_parent_is_a_cycle(self) -> None:
        with pytest.raises(VersionGraphCycleError):
            VersionGraph([_v("3.34", parents=("3.34",))])

    def test_two_node_cycle(self) -> None:
        # Two versions parenting each other — impossible in real
        # firmware history but the schema must reject it.
        with pytest.raises(VersionGraphCycleError):
            VersionGraph(
                [
                    _v("a", parents=("b",)),
                    _v("b", parents=("a",)),
                ]
            )

    def test_three_node_cycle(self) -> None:
        with pytest.raises(VersionGraphCycleError):
            VersionGraph(
                [
                    _v("a", parents=("c",)),
                    _v("b", parents=("a",)),
                    _v("c", parents=("b",)),
                ]
            )


# --- Path finding -------------------------------------------------


class TestPathFinding:
    def setup_method(self) -> None:
        # Linear chain plus a variant fork:
        #   3.34 -> 3.34B -> 3.35D
        #             \-> 3.34B-japan
        #
        # Plus a disconnected version "orphan".
        self.graph = VersionGraph(
            [
                _v("3.34"),
                _v("3.34B", parents=("3.34",)),
                _v("3.35D", parents=("3.34B",)),
                _v("3.34B-japan", parents=("3.34B",)),
                _v("orphan"),
            ]
        )

    def test_same_node_empty_path(self) -> None:
        assert self.graph.find_path("3.34", "3.34") == []

    def test_direct_parent_to_child(self) -> None:
        path = self.graph.find_path("3.34", "3.34B")
        assert len(path) == 1
        edge = path[0]
        assert edge.parent_id == "3.34"
        assert edge.child_id == "3.34B"
        assert edge.walked_forward is True

    def test_direct_child_to_parent_inverts(self) -> None:
        path = self.graph.find_path("3.34B", "3.34")
        assert len(path) == 1
        edge = path[0]
        assert edge.parent_id == "3.34"
        assert edge.child_id == "3.34B"
        assert edge.walked_forward is False  # walking against the edge

    def test_through_chain(self) -> None:
        path = self.graph.find_path("3.34", "3.35D")
        assert len(path) == 2
        assert all(e.walked_forward for e in path)
        assert [e.child_id for e in path] == ["3.34B", "3.35D"]

    def test_via_lca(self) -> None:
        # 3.35D and 3.34B-japan are siblings via 3.34B.
        path = self.graph.find_path("3.35D", "3.34B-japan")
        assert len(path) == 2
        # First edge: 3.35D up to 3.34B (backward)
        assert path[0].child_id == "3.35D"
        assert path[0].parent_id == "3.34B"
        assert path[0].walked_forward is False
        # Second edge: 3.34B down to 3.34B-japan (forward)
        assert path[1].parent_id == "3.34B"
        assert path[1].child_id == "3.34B-japan"
        assert path[1].walked_forward is True

    def test_disconnected_raises(self) -> None:
        with pytest.raises(NoPathError) as exc_info:
            self.graph.find_path("3.34", "orphan")
        assert exc_info.value.source_id == "3.34"
        assert exc_info.value.target_id == "orphan"

    def test_unknown_source(self) -> None:
        with pytest.raises(VersionNotInGraphError, match="source"):
            self.graph.find_path("nonexistent", "3.34")

    def test_unknown_target(self) -> None:
        with pytest.raises(VersionNotInGraphError, match="target"):
            self.graph.find_path("3.34", "nonexistent")

    def test_multi_parent_merge(self) -> None:
        # 3.40 has two parents — verify path-finding still works.
        graph = VersionGraph(
            [
                _v("a"),
                _v("b"),
                _v("merged", parents=("a", "b")),
            ]
        )
        path_from_a = graph.find_path("a", "merged")
        path_from_b = graph.find_path("b", "merged")
        assert len(path_from_a) == 1
        assert len(path_from_b) == 1


# --- Effective regions --------------------------------------------


class TestEffectiveRegions:
    def test_project_default(self) -> None:
        graph = VersionGraph(
            [_v("3.34")],
            project_regions=[Region(0x0016, 0x0076), Region(0x0D00, 0x0DFF)],
        )
        regions = graph.effective_regions("3.34")
        assert regions == [
            Region(0x0016, 0x0076),
            Region(0x0D00, 0x0DFF),
        ]

    def test_reloc_dests_added(self) -> None:
        graph = VersionGraph(
            [
                Version(
                    id="3.34",
                    parents=(),
                    reloc_blocks=(
                        RelocBlock(source=0x9000, dest=0x0400, length=0x100),
                    ),
                    explicit_regions=None,
                ),
            ],
            project_regions=[Region(0x0016, 0x0076)],
        )
        regions = graph.effective_regions("3.34")
        # Project default + reloc destination, sorted by start.
        assert regions == [
            Region(0x0016, 0x0076),
            Region(0x0400, 0x04FF),
        ]

    def test_explicit_override_replaces(self) -> None:
        graph = VersionGraph(
            [
                Version(
                    id="variant",
                    parents=(),
                    reloc_blocks=(),
                    explicit_regions=(Region(0x0700, 0x07FF),),
                ),
            ],
            project_regions=[Region(0x0016, 0x0076)],
        )
        regions = graph.effective_regions("variant")
        # Override completely replaces project regions.
        assert regions == [Region(0x0700, 0x07FF)]

    def test_override_plus_reloc(self) -> None:
        graph = VersionGraph(
            [
                Version(
                    id="variant",
                    parents=(),
                    reloc_blocks=(
                        RelocBlock(source=0x9999, dest=0x0500, length=0x100),
                    ),
                    explicit_regions=(Region(0x0700, 0x07FF),),
                ),
            ],
            project_regions=[Region(0x0016, 0x0076)],  # ignored
        )
        regions = graph.effective_regions("variant")
        assert regions == [
            Region(0x0500, 0x05FF),  # reloc dest still added
            Region(0x0700, 0x07FF),  # explicit override
        ]

    def test_overlapping_regions_merged(self) -> None:
        graph = VersionGraph(
            [
                Version(
                    id="3.34",
                    parents=(),
                    reloc_blocks=(
                        RelocBlock(source=0x9000, dest=0x0070, length=0x10),
                    ),
                    explicit_regions=None,
                ),
            ],
            project_regions=[Region(0x0016, 0x0076)],
        )
        regions = graph.effective_regions("3.34")
        # Reloc dest 0x70-0x7F overlaps with 0x16-0x76 — merged.
        assert regions == [Region(0x0016, 0x007F)]

    def test_adjacent_regions_merged(self) -> None:
        # 0x0000-0x00FF adjacent to 0x0100-0x01FF: merge into one.
        graph = VersionGraph(
            [_v("3.34")],
            project_regions=[
                Region(0x0000, 0x00FF),
                Region(0x0100, 0x01FF),
            ],
        )
        regions = graph.effective_regions("3.34")
        assert regions == [Region(0x0000, 0x01FF)]

    def test_unknown_version(self) -> None:
        graph = VersionGraph([_v("3.34")])
        with pytest.raises(VersionNotInGraphError):
            graph.effective_regions("nonexistent")


# --- Effective external regions ----------------------------------


class TestEffectiveExternalRegions:
    def test_project_only(self) -> None:
        graph = VersionGraph(
            [_v("3.34")],
            project_external_regions=[Region(0xFC00, 0xFFFF)],
        )
        assert graph.effective_external_regions("3.34") == [
            Region(0xFC00, 0xFFFF)
        ]

    def test_validates_version_exists(self) -> None:
        graph = VersionGraph(
            [_v("3.34")],
            project_external_regions=[Region(0xFC00, 0xFFFF)],
        )
        with pytest.raises(VersionNotInGraphError):
            graph.effective_external_regions("nonexistent")


# --- reloc_pairs_for_edge -----------------------------------------


class TestRelocPairsForEdge:
    def test_simple_pairing(self) -> None:
        # Both versions have the same reloc-block geometry; just the
        # source addresses differ.
        graph = VersionGraph(
            [
                Version(
                    id="3.34",
                    parents=(),
                    reloc_blocks=(
                        RelocBlock(source=0x9307, dest=0x0016, length=0x61),
                        RelocBlock(source=0x934C, dest=0x0400, length=0x100),
                    ),
                    explicit_regions=None,
                ),
                Version(
                    id="3.34B",
                    parents=("3.34",),
                    reloc_blocks=(
                        RelocBlock(source=0x9308, dest=0x0016, length=0x61),
                        RelocBlock(source=0x934D, dest=0x0400, length=0x100),
                    ),
                    explicit_regions=None,
                ),
            ]
        )
        edge = graph.find_path("3.34", "3.34B")[0]
        pairs = graph.reloc_pairs_for_edge(edge)
        assert pairs == [
            (0x9307, 0x9308, 0x0016, 0x61),
            (0x934C, 0x934D, 0x0400, 0x100),
        ]

    def test_independent_of_traversal_direction(self) -> None:
        graph = VersionGraph(
            [
                Version(
                    id="a",
                    parents=(),
                    reloc_blocks=(
                        RelocBlock(source=0x9000, dest=0x0400, length=0x100),
                    ),
                    explicit_regions=None,
                ),
                Version(
                    id="b",
                    parents=("a",),
                    reloc_blocks=(
                        RelocBlock(source=0x9010, dest=0x0400, length=0x100),
                    ),
                    explicit_regions=None,
                ),
            ]
        )
        # Walking forward (parent -> child).
        forward_edge = graph.find_path("a", "b")[0]
        forward_pairs = graph.reloc_pairs_for_edge(forward_edge)
        # Walking backward (child -> parent).
        backward_edge = graph.find_path("b", "a")[0]
        backward_pairs = graph.reloc_pairs_for_edge(backward_edge)
        # Tuples are oriented (parent, child) regardless of direction.
        assert forward_pairs == backward_pairs == [(0x9000, 0x9010, 0x0400, 0x100)]

    def test_unmatched_blocks_dropped(self) -> None:
        # Parent has a block at dest 0x0500 that the child doesn't.
        graph = VersionGraph(
            [
                Version(
                    id="parent",
                    parents=(),
                    reloc_blocks=(
                        RelocBlock(source=0x9000, dest=0x0400, length=0x100),
                        RelocBlock(source=0x9100, dest=0x0500, length=0x100),
                    ),
                    explicit_regions=None,
                ),
                Version(
                    id="child",
                    parents=("parent",),
                    reloc_blocks=(
                        RelocBlock(source=0x9010, dest=0x0400, length=0x100),
                    ),
                    explicit_regions=None,
                ),
            ]
        )
        edge = graph.find_path("parent", "child")[0]
        pairs = graph.reloc_pairs_for_edge(edge)
        # Only the matched block appears.
        assert pairs == [(0x9000, 0x9010, 0x0400, 0x100)]

    def test_empty_when_no_reloc_blocks(self) -> None:
        graph = VersionGraph(
            [_v("a"), _v("b", parents=("a",))]
        )
        edge = graph.find_path("a", "b")[0]
        assert graph.reloc_pairs_for_edge(edge) == []

    def test_duplicate_keys_paired_positionally(self) -> None:
        # Both versions have two reloc blocks with the same (dest, length)
        # — pair them off in order.
        graph = VersionGraph(
            [
                Version(
                    id="a",
                    parents=(),
                    reloc_blocks=(
                        RelocBlock(source=0x9000, dest=0x0400, length=0x100),
                        RelocBlock(source=0x9100, dest=0x0400, length=0x100),
                    ),
                    explicit_regions=None,
                ),
                Version(
                    id="b",
                    parents=("a",),
                    reloc_blocks=(
                        RelocBlock(source=0x9010, dest=0x0400, length=0x100),
                        RelocBlock(source=0x9110, dest=0x0400, length=0x100),
                    ),
                    explicit_regions=None,
                ),
            ]
        )
        edge = graph.find_path("a", "b")[0]
        pairs = graph.reloc_pairs_for_edge(edge)
        # Sorted by parent source: (0x9000, 0x9010, ...) then (0x9100, 0x9110, ...).
        assert pairs == [
            (0x9000, 0x9010, 0x0400, 0x100),
            (0x9100, 0x9110, 0x0400, 0x100),
        ]


# --- load_version_graph -------------------------------------------


def _project_with_config(tmp_path, config: dict) -> ProjectContext:
    """Build a ProjectContext directly with the given config dict."""
    return ProjectContext(
        root_dirpath=tmp_path,
        config_filepath=tmp_path / "fantasm.toml",
        config=config,
    )


class TestLoadVersionGraph:
    def test_minimal_config(self, tmp_path) -> None:
        project = _project_with_config(tmp_path, {})
        graph = load_version_graph(project)
        assert len(graph) == 0

    def test_full_config(self, tmp_path) -> None:
        config = {
            "memory": {
                "regions": [{"start": 0x0016, "end": 0x0076}],
                "external_regions": [{"start": 0xFC00, "end": 0xFFFF}],
            },
            "versions": {
                "entry": [
                    {
                        "id": "3.34",
                        "parents": [],
                        "reloc_blocks": [
                            {"source": 0x9307, "dest": 0x0016, "length": 0x61},
                        ],
                    },
                    {
                        "id": "3.34B",
                        "parents": ["3.34"],
                        "reloc_blocks": [
                            {"source": 0x9308, "dest": 0x0016, "length": 0x61},
                        ],
                    },
                ],
            },
        }
        project = _project_with_config(tmp_path, config)
        graph = load_version_graph(project)
        assert graph.ids() == ("3.34", "3.34B")
        # Path-finding works.
        path = graph.find_path("3.34", "3.34B")
        assert len(path) == 1
        # Effective regions include reloc dest.
        regions = graph.effective_regions("3.34")
        assert Region(0x0016, 0x0076) in regions

    def test_per_version_memory_override(self, tmp_path) -> None:
        config = {
            "memory": {
                "regions": [{"start": 0x0016, "end": 0x0076}],
            },
            "versions": {
                "entry": [
                    {
                        "id": "variant",
                        "memory": {
                            "regions": [
                                {"start": 0x0700, "end": 0x07FF},
                            ],
                        },
                    },
                ],
            },
        }
        project = _project_with_config(tmp_path, config)
        graph = load_version_graph(project)
        # Override replaces project regions (no reloc dests in this entry).
        assert graph.effective_regions("variant") == [Region(0x0700, 0x07FF)]

    def test_unresolved_project_raises(self) -> None:
        empty = ProjectContext(root_dirpath=None)
        with pytest.raises(RuntimeError, match="Project root"):
            load_version_graph(empty)

    def test_missing_id_field_rejected(self, tmp_path) -> None:
        config = {
            "versions": {
                "entry": [{"parents": []}],
            },
        }
        project = _project_with_config(tmp_path, config)
        with pytest.raises(VersionGraphError, match="'id'"):
            load_version_graph(project)

    def test_metadata_fields_carried_through(self, tmp_path) -> None:
        config = {
            "versions": {
                "entry": [
                    {
                        "id": "3.34",
                        "notes": "first release",
                        "description": "zero-based layout",
                        "release_date": "1984-01-15",
                        "source": "Acorn archive #001",
                    },
                ],
            },
        }
        project = _project_with_config(tmp_path, config)
        graph = load_version_graph(project)
        v = graph.get("3.34")
        assert v.notes == "first release"
        assert v.description == "zero-based layout"
        assert v.release_date == "1984-01-15"
        assert v.source == "Acorn archive #001"
