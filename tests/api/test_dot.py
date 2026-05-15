"""Tests for fantasm.api.dot — graphviz/GraphML emission and filtering."""

from __future__ import annotations

import shutil

import networkx as nx
import pytest

from fantasm.api.cfg import find_basic_blocks
from fantasm.api.dot import (
    DotBinaryNotFoundError,
    basic_blocks_to_dot,
    basic_blocks_to_graph,
    basic_blocks_to_graphml,
    call_graph_to_dot,
    call_graph_to_graphml,
    filter_call_graph,
    render_dot,
)
from fantasm.api.dot import _dot_label, _escape_dot_text, _format_attrs, _Raw


def _make_call_graph() -> nx.DiGraph:
    """Three internal subs and one external OS entry.

    main -> helper -> leaf
                    \\-> oswrch (external)
    """
    graph: nx.DiGraph = nx.DiGraph()
    graph.add_node(
        "0x8000", name="main", title="ROM entry", external=False
    )
    graph.add_node(
        "0x8100", name="helper", title="", external=False
    )
    graph.add_node(
        "0x8200", name="leaf", title="", external=False
    )
    graph.add_node(
        "0xFFEE", name="oswrch", title="", external=True
    )
    graph.add_edge(
        "0x8000", "0x8100", type="jsr", call_sites=["0x8005"]
    )
    graph.add_edge(
        "0x8100", "0x8200", type="jmp", call_sites=["0x8120"]
    )
    graph.add_edge(
        "0x8100", "0xFFEE", type="jsr", call_sites=["0x8110", "0x8118"]
    )
    return graph


def _make_branch_blocks() -> list:
    """Two-block routine with a conditional branch + fall-through + rts."""
    items = [
        {"addr": 0x8000, "type": "code", "mnemonic": "lda", "operand": "&70",
         "labels": ["my_sub"]},
        {"addr": 0x8002, "type": "code", "mnemonic": "cmp", "operand": "#&0d"},
        {"addr": 0x8004, "type": "code", "mnemonic": "beq", "operand": "done",
         "target": 0x8008},
        {"addr": 0x8006, "type": "code", "mnemonic": "lda", "operand": "#1"},
        {"addr": 0x8008, "type": "code", "mnemonic": "rts",
         "comment_inline": "return"},
    ]
    return find_basic_blocks(items)


# --- Escaping primitives -------------------------------------------


def test_escape_dot_text_doubles_backslashes() -> None:
    assert _escape_dot_text(r"path\to\thing") == r"path\\to\\thing"


def test_escape_dot_text_escapes_quotes() -> None:
    assert _escape_dot_text('say "hi"') == 'say \\"hi\\"'


def test_escape_dot_text_converts_real_newlines() -> None:
    # A literal newline in source text becomes the dot escape sequence
    # \n (two characters), so the rendered label breaks on a new line
    # rather than embedding a raw newline in the dot file.
    assert _escape_dot_text("a\nb") == "a\\nb"


def test_dot_label_joins_with_newline_by_default() -> None:
    label = _dot_label("first", "second")
    assert isinstance(label, _Raw)
    assert label.text == '"first\\nsecond"'


def test_dot_label_escapes_each_part() -> None:
    label = _dot_label('say "hi"', "path\\here")
    assert label.text == '"say \\"hi\\"\\npath\\\\here"'


def test_format_attrs_emits_raw_verbatim() -> None:
    out = _format_attrs({"label": _Raw('"a\\nb"'), "shape": "box"})
    assert 'label="a\\nb"' in out
    assert 'shape="box"' in out


# --- call_graph_to_dot ----------------------------------------------


def test_call_graph_dot_starts_with_digraph() -> None:
    graph = _make_call_graph()
    text = call_graph_to_dot(graph, title="demo")
    assert text.startswith('digraph "demo" {')
    assert text.rstrip().endswith("}")


def test_call_graph_dot_includes_all_nodes() -> None:
    graph = _make_call_graph()
    text = call_graph_to_dot(graph)
    for node_id in ("0x8000", "0x8100", "0x8200", "0xFFEE"):
        assert f'"{node_id}"' in text


def test_call_graph_dot_label_is_just_the_name() -> None:
    graph = _make_call_graph()
    text = call_graph_to_dot(graph)
    # Pre-refactor labels carried `\n` between name and address and
    # rendered as literal "\n" in the image because of double-
    # escaping. The current label is the bare name; the address is
    # already in the node id.
    helper_line = next(
        l for l in text.splitlines() if l.startswith('  "0x8100"')
    )
    assert 'label="helper"' in helper_line
    assert "\\n" not in helper_line


def test_call_graph_dot_marks_external_with_doubleoctagon() -> None:
    graph = _make_call_graph()
    text = call_graph_to_dot(graph)
    # Find the line for 0xFFEE.
    line = next(l for l in text.splitlines() if '"0xFFEE"' in l and "shape" in l)
    assert "doubleoctagon" in line


def test_call_graph_dot_marks_root_with_hexagon() -> None:
    graph = _make_call_graph()
    text = call_graph_to_dot(graph)
    # main has no incoming edges -> hexagon
    line = next(l for l in text.splitlines() if '"0x8000"' in l and "shape" in l)
    assert "hexagon" in line


def test_call_graph_dot_styles_jmp_dashed() -> None:
    graph = _make_call_graph()
    text = call_graph_to_dot(graph)
    # The 0x8100 -> 0x8200 edge is a jmp (tail-call).
    edge_line = next(
        l for l in text.splitlines() if '"0x8100" -> "0x8200"' in l
    )
    assert "dashed" in edge_line
    assert "jmp" in edge_line


def test_call_graph_dot_labels_repeated_call_sites() -> None:
    graph = _make_call_graph()
    text = call_graph_to_dot(graph)
    edge_line = next(
        l for l in text.splitlines() if '"0x8100" -> "0xFFEE"' in l
    )
    assert "2×" in edge_line


# --- filter_call_graph ---------------------------------------------


def test_filter_call_graph_excludes_external() -> None:
    graph = _make_call_graph()
    filtered = filter_call_graph(graph, exclude_external=True)
    assert "0xFFEE" not in filtered.nodes
    assert "0x8000" in filtered.nodes


def test_filter_call_graph_focus_with_depth() -> None:
    graph = _make_call_graph()
    # Focus on helper, descendants only, depth 1.
    filtered = filter_call_graph(
        graph, focus=["helper"], up_depth=0, down_depth=1
    )
    assert "0x8100" in filtered.nodes
    assert "0x8200" in filtered.nodes
    assert "0xFFEE" in filtered.nodes
    assert "0x8000" not in filtered.nodes  # parent excluded


def test_filter_call_graph_focus_marks_focused_attribute() -> None:
    graph = _make_call_graph()
    filtered = filter_call_graph(graph, focus=["helper"], up_depth=0, down_depth=0)
    assert filtered.nodes["0x8100"].get("focused") is True


def test_filter_call_graph_include_pattern() -> None:
    graph = _make_call_graph()
    filtered = filter_call_graph(graph, include_pattern=r"^(main|helper)$")
    assert set(filtered.nodes) == {"0x8000", "0x8100"}


def test_filter_call_graph_min_degree_drops_isolates() -> None:
    graph = _make_call_graph()
    # leaf has degree 1; main has degree 1; helper has degree 3.
    filtered = filter_call_graph(graph, min_degree=2)
    assert "0x8100" in filtered.nodes
    assert "0x8000" not in filtered.nodes
    assert "0x8200" not in filtered.nodes


def test_filter_call_graph_unknown_focus_raises() -> None:
    graph = _make_call_graph()
    with pytest.raises(ValueError, match="not found"):
        filter_call_graph(graph, focus=["nonexistent_sub_name"])


# --- basic_blocks_to_graph / _to_dot --------------------------------


def test_basic_blocks_to_graph_node_count() -> None:
    blocks = _make_branch_blocks()
    graph = basic_blocks_to_graph(
        blocks, sub_name="my_sub", sub_addr=0x8000
    )
    # Two real blocks: 0x8000 (start, ends with beq) and 0x8008 (rts target).
    # 0x8006 is unreachable-as-block-start from labels but follows the
    # branch's fall-through, so it should also be a block.
    addrs = {graph.nodes[n]["addr"] for n in graph.nodes if not graph.nodes[n]["external"]}
    assert 0x8000 in addrs
    assert 0x8008 in addrs


def test_basic_blocks_to_dot_starts_with_digraph() -> None:
    blocks = _make_branch_blocks()
    text = basic_blocks_to_dot(blocks, sub_name="my_sub", sub_addr=0x8000)
    assert text.startswith('digraph')
    assert '"my_sub (&8000)"' in text
    assert "rankdir=TB" in text


def test_basic_blocks_to_dot_colours_edges_by_kind() -> None:
    blocks = _make_branch_blocks()
    text = basic_blocks_to_dot(blocks)
    # Branch (taken) edge: blue (#268bd2).
    # Fall-through edge: green (#859900).
    assert "#268bd2" in text  # branch
    assert "#859900" in text  # fall


def test_basic_blocks_to_dot_marks_return_block_distinctly() -> None:
    blocks = _make_branch_blocks()
    text = basic_blocks_to_dot(blocks)
    # The rts block (0x8008) should have a red border + bold.
    rts_node_id = "blk_8008"
    rts_line = next(
        l for l in text.splitlines() if f'"{rts_node_id}"' in l and "label" in l
    )
    assert "rounded,filled,bold" in rts_line


def test_basic_blocks_to_dot_renders_instructions_in_label() -> None:
    blocks = _make_branch_blocks()
    text = basic_blocks_to_dot(blocks)
    # The lda &70 instruction should appear in the label table.
    assert "lda &amp;70" in text
    # The comment on the rts should appear as italicised aside.
    assert "return" in text


def test_basic_blocks_to_dot_html_escapes_ampersand() -> None:
    blocks = _make_branch_blocks()
    text = basic_blocks_to_dot(blocks)
    # The header shows &XXXX as &amp;XXXX in HTML labels.
    assert "&amp;8000" in text


# --- GraphML -------------------------------------------------------


def test_call_graph_to_graphml_is_well_formed_xml() -> None:
    graph = _make_call_graph()
    text = call_graph_to_graphml(graph)
    assert text.startswith("<?xml")
    assert "<graphml" in text
    assert "0x8000" in text


def test_basic_blocks_to_graphml_substitutes_plain_label() -> None:
    blocks = _make_branch_blocks()
    text = basic_blocks_to_graphml(blocks, sub_name="my_sub", sub_addr=0x8000)
    # HTML labels would contain "<" which GraphML can't carry as a node
    # label; the converter replaces them with "&XXXX" plaintext.
    assert "<TABLE" not in text
    assert "&amp;8000" in text or "&#38;8000" in text


# --- render_dot ----------------------------------------------------


def _dot_on_path() -> bool:
    return shutil.which("dot") is not None


@pytest.mark.skipif(
    _dot_on_path(),
    reason="graphviz dot is installed; this test exercises the missing-binary path",
)
def test_render_dot_raises_when_engine_missing(tmp_path) -> None:
    with pytest.raises(DotBinaryNotFoundError):
        render_dot("digraph G { a -> b; }", tmp_path / "out.png")


@pytest.mark.skipif(
    not _dot_on_path(),
    reason="graphviz dot not on PATH",
)
def test_render_dot_produces_png(tmp_path) -> None:
    graph = _make_call_graph()
    text = call_graph_to_dot(graph)
    output_filepath = tmp_path / "out.png"
    render_dot(text, output_filepath, format="png")
    assert output_filepath.exists()
    assert output_filepath.stat().st_size > 0
    # PNG magic bytes.
    assert output_filepath.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
