"""Tests for ``fantasm.api.insert_point``, ``cfg``, and ``context``."""

from __future__ import annotations

import json
from pathlib import Path

import networkx as nx
import pytest

from fantasm.api.cfg import (
    BasicBlock,
    BasicBlockExit,
    build_call_graph,
    find_basic_blocks,
    resolve_sub_node,
)
from fantasm.api.context import (
    CallSiteContext,
    ExitPointContext,
    SubContext,
    compute_call_depths,
    extract_sub_context,
)
from fantasm.api.insert_point import (
    AlreadyDeclared,
    compute_insert_point,
    find_main_block,
    parse_subroutine_declarations,
)


# --- insert_point --------------------------------------------------


SAMPLE_DRIVER = [
    "import py8dis",
    "",
    "# =================== Setup ===================",
    'setup_call(0x8000, "init", ...)',
    "",
    "# =================== Subroutines correspondence ===================",
    'subroutine(0x8000, "init_state", hook=None)',
    'subroutine(0x8050,',
    '    "load_data",',
    '    hook=None)',
    'subroutine(0x8100, "save_data")',
    "",
    "# =================== End ===================",
    "tail()",
]


class TestParseSubroutineDeclarations:
    def test_parses_three_decls(self) -> None:
        decls = parse_subroutine_declarations(SAMPLE_DRIVER)
        assert len(decls) == 3
        addrs = [d["addr"] for d in decls]
        assert addrs == [0x8000, 0x8050, 0x8100]

    def test_multi_line_call_end(self) -> None:
        decls = parse_subroutine_declarations(SAMPLE_DRIVER)
        load_data = next(d for d in decls if d["addr"] == 0x8050)
        # Multi-line call: end_line should differ from start_line.
        assert load_data["start_line"] != load_data["end_line"]

    def test_extracts_names_from_single_line(self) -> None:
        decls = parse_subroutine_declarations(SAMPLE_DRIVER)
        names = [d["name"] for d in decls]
        # Multi-line declarations whose name is on a later line return
        # None — pinning down the sibling parser behaviour, which only
        # looks at the opening line. (load_data is multi-line in the
        # fixture.)
        assert names == ["init_state", None, "save_data"]


class TestFindMainBlock:
    def test_finds_correspondence_section(self) -> None:
        decls = parse_subroutine_declarations(SAMPLE_DRIVER)
        block_start, block_end = find_main_block(SAMPLE_DRIVER, decls)
        # Block starts at the "# Subroutines correspondence" header.
        assert SAMPLE_DRIVER[block_start].startswith(
            "# =================== Subroutines"
        )
        # Block ends before the next section header.
        assert "End" in SAMPLE_DRIVER[block_end + 1]


class TestComputeInsertPoint:
    def test_between_two(self) -> None:
        ip = compute_insert_point(SAMPLE_DRIVER, 0x8080)
        assert ip.predecessor is not None
        assert ip.predecessor["addr"] == 0x8050
        assert ip.successor is not None
        assert ip.successor["addr"] == 0x8100

    def test_already_declared_raises(self) -> None:
        with pytest.raises(AlreadyDeclared) as exc:
            compute_insert_point(SAMPLE_DRIVER, 0x8050)
        assert exc.value.declaration["addr"] == 0x8050

    def test_no_declarations_raises(self) -> None:
        with pytest.raises(LookupError, match="no subroutine"):
            compute_insert_point(["import py8dis", "tail()"], 0x8050)

    def test_before_first(self) -> None:
        ip = compute_insert_point(SAMPLE_DRIVER, 0x7000)
        assert ip.predecessor is None
        assert ip.successor is not None
        assert ip.successor["addr"] == 0x8000

    def test_after_last(self) -> None:
        ip = compute_insert_point(SAMPLE_DRIVER, 0x9000)
        assert ip.predecessor is not None
        assert ip.predecessor["addr"] == 0x8100
        assert ip.successor is None


# --- cfg -----------------------------------------------------------


def _write_call_graph_disasm(tmp_path: Path) -> Path:
    """Two ROM subs where the first JSRs the second."""
    data = {
        "meta": {"load_addr": 0x8000, "end_addr": 0x8100},
        "subroutines": [
            {"addr": 0x8000, "name": "main"},
            {"addr": 0x8020, "name": "helper"},
        ],
        "external_labels": {"oswrch": 0xFFEE},
        "items": [
            {"addr": 0x8000, "type": "code", "mnemonic": "lda"},
            {
                "addr": 0x8002,
                "type": "code",
                "mnemonic": "jsr",
                "target": 0x8020,
            },
            {
                "addr": 0x8005,
                "type": "code",
                "mnemonic": "jsr",
                "target": 0xFFEE,
            },
            {"addr": 0x8008, "type": "code", "mnemonic": "rts"},
            {"addr": 0x8020, "type": "code", "mnemonic": "lda"},
            {"addr": 0x8022, "type": "code", "mnemonic": "rts"},
        ],
    }
    json_filepath = tmp_path / "out.json"
    json_filepath.write_text(json.dumps(data))
    return json_filepath


class TestBuildCallGraph:
    def test_nodes_and_edges(self, tmp_path: Path) -> None:
        graph = build_call_graph(_write_call_graph_disasm(tmp_path))
        # Two ROM subs + the external os call.
        assert "0x8000" in graph.nodes
        assert "0x8020" in graph.nodes
        assert "0xFFEE" in graph.nodes
        # main calls helper and oswrch.
        assert graph.has_edge("0x8000", "0x8020")
        assert graph.has_edge("0x8000", "0xFFEE")

    def test_external_flag(self, tmp_path: Path) -> None:
        graph = build_call_graph(_write_call_graph_disasm(tmp_path))
        assert graph.nodes["0x8020"]["external"] is False
        assert graph.nodes["0xFFEE"]["external"] is True

    def test_call_sites_sorted(self, tmp_path: Path) -> None:
        graph = build_call_graph(_write_call_graph_disasm(tmp_path))
        sites = graph["0x8000"]["0x8020"]["call_sites"]
        assert sites == sorted(sites)


class TestResolveSubNode:
    def test_by_hex_address(self, tmp_path: Path) -> None:
        graph = build_call_graph(_write_call_graph_disasm(tmp_path))
        assert resolve_sub_node(graph, "0x8020") == "0x8020"
        assert resolve_sub_node(graph, "8020") == "0x8020"
        assert resolve_sub_node(graph, "&8020") == "0x8020"

    def test_by_name(self, tmp_path: Path) -> None:
        graph = build_call_graph(_write_call_graph_disasm(tmp_path))
        assert resolve_sub_node(graph, "helper") == "0x8020"

    def test_unknown_returns_none(self, tmp_path: Path) -> None:
        graph = build_call_graph(_write_call_graph_disasm(tmp_path))
        assert resolve_sub_node(graph, "nope") is None


# --- context -------------------------------------------------------


class TestComputeCallDepths:
    def test_linear_chain(self) -> None:
        graph: nx.DiGraph = nx.DiGraph()
        graph.add_node("a", external=False)
        graph.add_node("b", external=False)
        graph.add_node("c", external=False)
        graph.add_edge("a", "b")
        graph.add_edge("b", "c")
        depths = compute_call_depths(graph)
        assert depths["c"] == 0
        assert depths["b"] == 1
        assert depths["a"] == 2

    def test_external_nodes_excluded(self) -> None:
        graph: nx.DiGraph = nx.DiGraph()
        graph.add_node("a", external=False)
        graph.add_node("os", external=True)
        graph.add_edge("a", "os")
        depths = compute_call_depths(graph)
        assert "os" not in depths
        # 'a' calls only an external node, so internally a leaf.
        assert depths["a"] == 0

    def test_cycle_collapsed_via_scc(self) -> None:
        graph: nx.DiGraph = nx.DiGraph()
        graph.add_node("a", external=False)
        graph.add_node("b", external=False)
        graph.add_edge("a", "b")
        graph.add_edge("b", "a")  # cycle
        depths = compute_call_depths(graph)
        # Both nodes share the same depth from SCC condensation.
        assert depths["a"] == depths["b"]


# --- extract_sub_context -----------------------------------------


SUB_CONTEXT_ASM = [
    "; header\n",
    ".main\n",
    "    LDA #$00       ;8000:\n",
    "    JSR helper     ;8002:\n",
    "    NOP            ;8005:\n",
    "    RTS            ;8006:\n",
    "\n",
    ".helper\n",
    "    LDX #$10       ;8010:\n",
    "    DEX            ;8012:\n",
    "    BNE :8012[1]   ;8013:\n",
    "    RTS            ;8015:\n",
]

SUB_CONTEXT_HELPER_SUB = {
    "addr": 0x8010,
    "name": "helper",
    "title": "Helper routine",
    "items": [
        {"addr": 0x8010, "type": "code", "mnemonic": "ldx"},
        {"addr": 0x8012, "type": "code", "mnemonic": "dex"},
        {"addr": 0x8013, "type": "code", "mnemonic": "bne", "target": 0x8012},
        {"addr": 0x8015, "type": "code", "mnemonic": "rts"},
    ],
    "next_sub": None,
}


def _call_graph_with_main_calling_helper() -> nx.DiGraph:
    graph: nx.DiGraph = nx.DiGraph()
    graph.add_node("0x8000", name="main", external=False)
    graph.add_node("0x8010", name="helper", external=False)
    graph.add_edge(
        "0x8000", "0x8010", call_sites=["0x8002"], type="jsr"
    )
    return graph


class TestExtractSubContext:
    def test_body_lines(self) -> None:
        sub_context = extract_sub_context(
            SUB_CONTEXT_HELPER_SUB,
            SUB_CONTEXT_ASM,
            _call_graph_with_main_calling_helper(),
            body_window=4,
        )
        assert sub_context.name == "helper"
        assert sub_context.addr == 0x8010
        # Body starts at the .helper line.
        body_text = "".join(sub_context.body_lines)
        assert "LDX" in body_text

    def test_call_sites_from_graph(self) -> None:
        sub_context = extract_sub_context(
            SUB_CONTEXT_HELPER_SUB,
            SUB_CONTEXT_ASM,
            _call_graph_with_main_calling_helper(),
        )
        assert len(sub_context.call_sites) == 1
        site = sub_context.call_sites[0]
        assert site.addr == 0x8002
        assert site.mnemonic == "jsr"
        assert site.in_sub_name == "main"
        # Window includes the JSR line.
        assert any("JSR helper" in line for line in site.asm_lines)

    def test_exit_points(self) -> None:
        sub_context = extract_sub_context(
            SUB_CONTEXT_HELPER_SUB,
            SUB_CONTEXT_ASM,
            _call_graph_with_main_calling_helper(),
        )
        assert len(sub_context.exit_points) == 1
        exit_point = sub_context.exit_points[0]
        assert exit_point.addr == 0x8015
        assert exit_point.mnemonic == "rts"
        # Exit context backs up before the RTS.
        assert any("RTS" in line for line in exit_point.asm_lines)

    def test_no_callers(self) -> None:
        # An isolated sub with no callers should produce empty
        # call_sites without erroring.
        graph: nx.DiGraph = nx.DiGraph()
        graph.add_node("0x8010", name="helper", external=False)
        sub_context = extract_sub_context(
            SUB_CONTEXT_HELPER_SUB, SUB_CONTEXT_ASM, graph
        )
        assert sub_context.call_sites == ()


# --- find_basic_blocks -------------------------------------------


class TestFindBasicBlocks:
    def test_straight_line(self) -> None:
        # Three sequential code items with no branches → one block.
        items = [
            {"addr": 0x8000, "type": "code", "mnemonic": "lda"},
            {"addr": 0x8002, "type": "code", "mnemonic": "sta"},
            {"addr": 0x8004, "type": "code", "mnemonic": "rts"},
        ]
        blocks = find_basic_blocks(items)
        assert len(blocks) == 1
        assert blocks[0].addr == 0x8000
        assert blocks[0].total == 3
        # The RTS produces a "return" exit with target=None.
        assert blocks[0].exits == (BasicBlockExit(None, "return"),)

    def test_branch_creates_two_blocks(self) -> None:
        # A conditional branch splits into two blocks.
        items = [
            {"addr": 0x8000, "type": "code", "mnemonic": "lda"},
            {
                "addr": 0x8002,
                "type": "code",
                "mnemonic": "bne",
                "target": 0x8006,
            },
            {"addr": 0x8004, "type": "code", "mnemonic": "nop"},
            {"addr": 0x8006, "type": "code", "mnemonic": "rts"},
        ]
        blocks = find_basic_blocks(items)
        addrs = sorted(b.addr for b in blocks)
        # 0x8000 (start), 0x8004 (after branch), 0x8006 (branch target).
        assert addrs == [0x8000, 0x8004, 0x8006]

    def test_entries_filled_from_exits(self) -> None:
        items = [
            {
                "addr": 0x8000,
                "type": "code",
                "mnemonic": "bne",
                "target": 0x8004,
            },
            {"addr": 0x8002, "type": "code", "mnemonic": "rts"},
            {"addr": 0x8004, "type": "code", "mnemonic": "rts"},
        ]
        blocks = find_basic_blocks(items)
        target_block = next(b for b in blocks if b.addr == 0x8004)
        # Entered by the branch from 0x8000.
        assert any(
            entry.source == 0x8000 and entry.kind == "branch"
            for entry in target_block.entries
        )

    def test_label_starts_a_block(self) -> None:
        # An item carrying a label is itself a block start, even with
        # no branch leading to it directly.
        items = [
            {"addr": 0x8000, "type": "code", "mnemonic": "lda"},
            {
                "addr": 0x8002,
                "type": "code",
                "mnemonic": "sta",
                "labels": ["middle"],
            },
            {"addr": 0x8004, "type": "code", "mnemonic": "rts"},
        ]
        blocks = find_basic_blocks(items)
        addrs = sorted(b.addr for b in blocks)
        assert 0x8002 in addrs

    def test_skips_non_code_items(self) -> None:
        items = [
            {"addr": 0x8000, "type": "code", "mnemonic": "lda"},
            {"addr": 0x8002, "type": "byte"},
            {"addr": 0x8003, "type": "code", "mnemonic": "rts"},
        ]
        blocks = find_basic_blocks(items)
        assert all(
            all(item.get("type") == "code" for item in block.items)
            for block in blocks
        )

    def test_commented_count(self) -> None:
        items = [
            {
                "addr": 0x8000,
                "type": "code",
                "mnemonic": "lda",
                "comment_inline": "load",
            },
            {"addr": 0x8002, "type": "code", "mnemonic": "rts"},
        ]
        blocks = find_basic_blocks(items)
        assert blocks[0].commented == 1
        assert blocks[0].total == 2

    def test_empty_input(self) -> None:
        assert find_basic_blocks([]) == []
