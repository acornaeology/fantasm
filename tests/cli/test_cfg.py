"""Tests for ``fantasm cfg`` subcommands."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project, write_minimal_disasm


def _write_branching_disasm(version_dirpath: Path, prefix: str, version_id: str) -> Path:
    """Write a 2-block, 2-subroutine disassembly suitable for graph tests."""
    output_dirpath = version_dirpath / "output"
    output_dirpath.mkdir(exist_ok=True)
    json_filepath = output_dirpath / f"{prefix}-{version_id}.json"
    json_filepath.write_text(
        json.dumps({
            "meta": {"load_addr": 0x8000, "end_addr": 0x8100},
            "subroutines": [
                {"addr": 0x8000, "name": "caller"},
                {"addr": 0x8020, "name": "callee"},
            ],
            "items": [
                {"addr": 0x8000, "type": "code", "mnemonic": "lda",
                 "operand": "#0", "labels": ["caller"]},
                {"addr": 0x8002, "type": "code", "mnemonic": "jsr",
                 "operand": "callee", "target": 0x8020},
                {"addr": 0x8005, "type": "code", "mnemonic": "beq",
                 "operand": "skip", "target": 0x800A},
                {"addr": 0x8007, "type": "code", "mnemonic": "lda",
                 "operand": "#1"},
                {"addr": 0x8009, "type": "code", "mnemonic": "rts"},
                {"addr": 0x800A, "type": "code", "mnemonic": "nop",
                 "labels": ["skip"]},
                {"addr": 0x800B, "type": "code", "mnemonic": "rts"},
                {"addr": 0x8020, "type": "code", "mnemonic": "lda",
                 "operand": "#&FF", "labels": ["callee"]},
                {"addr": 0x8022, "type": "code", "mnemonic": "rts"},
            ],
        })
    )
    return json_filepath


def test_cfg_leaves(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    write_minimal_disasm(version_dirpath, "demo", "1.0")

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "cfg", "leaves", "1.0", "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output


def test_cfg_blocks(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    json_filepath = version_dirpath / "output" / "demo-1.0.json"
    json_filepath.parent.mkdir(exist_ok=True)
    # Two blocks of two items each, joined by a conditional branch.
    json_filepath.write_text(
        json.dumps({
            "meta": {"load_addr": 0x8000, "end_addr": 0x8100},
            "subroutines": [{"addr": 0x8000, "name": "main"}],
            "items": [
                {"addr": 0x8000, "type": "code", "mnemonic": "lda"},
                {
                    "addr": 0x8002,
                    "type": "code",
                    "mnemonic": "bne",
                    "target": 0x8006,
                },
                {"addr": 0x8004, "type": "code", "mnemonic": "nop"},
                {"addr": 0x8005, "type": "code", "mnemonic": "rts"},
                {"addr": 0x8006, "type": "code", "mnemonic": "ldx"},
                {"addr": 0x8008, "type": "code", "mnemonic": "rts"},
            ],
        })
    )

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "cfg", "blocks", "1.0", "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "8000" in result.output
    assert "8006" in result.output


def test_cfg_sub_context(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    json_filepath = version_dirpath / "output" / "demo-1.0.json"
    json_filepath.parent.mkdir(exist_ok=True)
    json_filepath.write_text(
        json.dumps({
            "meta": {"load_addr": 0x8000, "end_addr": 0x8100},
            "subroutines": [{"addr": 0x8000, "name": "main"}],
            "items": [
                {"addr": 0x8000, "type": "code", "mnemonic": "lda"},
                {"addr": 0x8002, "type": "code", "mnemonic": "rts"},
            ],
        })
    )
    asm_filepath = version_dirpath / "output" / "demo-1.0.asm"
    asm_filepath.write_text(
        ".main\n"
        "    LDA #$00       ;8000:\n"
        "    RTS            ;8002:\n"
    )

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "cfg", "sub-context", "1.0", "main", "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "main" in result.output


def test_cfg_depth(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    write_minimal_disasm(version_dirpath, "demo", "1.0")

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "cfg", "depth", "1.0", "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output


def test_cfg_dot_call_graph_to_stdout(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    _write_branching_disasm(version_dirpath, "demo", "1.0")

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "cfg", "dot-call-graph", "1.0",
        ],
    )
    assert result.exit_code == 0, result.output
    assert result.output.startswith("digraph ")
    assert '"0x8000"' in result.output
    assert '"0x8020"' in result.output
    assert "->" in result.output


def test_cfg_dot_call_graph_filter_focus(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    _write_branching_disasm(version_dirpath, "demo", "1.0")

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "cfg", "dot-call-graph", "1.0",
            "--focus", "callee",
            "--down-depth", "0",
            "--up-depth", "0",
        ],
    )
    assert result.exit_code == 0, result.output
    assert '"0x8020"' in result.output
    # Caller node should be excluded with depth 0.
    assert '"0x8000"' not in result.output


def test_cfg_dot_call_graph_to_file(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    _write_branching_disasm(version_dirpath, "demo", "1.0")
    out_filepath = tmp_path / "graph.dot"

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "cfg", "dot-call-graph", "1.0",
            "-o", str(out_filepath),
        ],
    )
    assert result.exit_code == 0, result.output
    assert out_filepath.exists()
    assert out_filepath.read_text().startswith("digraph ")


def test_cfg_dot_call_graph_graphml_format(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    _write_branching_disasm(version_dirpath, "demo", "1.0")

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "cfg", "dot-call-graph", "1.0",
            "--format", "graphml",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "<graphml" in result.output


def test_cfg_dot_flow_to_stdout(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    _write_branching_disasm(version_dirpath, "demo", "1.0")

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "cfg", "dot-flow", "1.0", "caller",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "digraph" in result.output
    # The instruction text should be present in HTML-escaped form.
    assert "lda" in result.output
    # The first block carries the "caller" label.
    assert "caller" in result.output


def test_cfg_dot_flow_unknown_sub_errors(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    _write_branching_disasm(version_dirpath, "demo", "1.0")

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "cfg", "dot-flow", "1.0", "no_such_sub",
        ],
    )
    assert result.exit_code != 0


def test_cfg_dot_render_requires_output(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    _write_branching_disasm(version_dirpath, "demo", "1.0")

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "cfg", "dot-call-graph", "1.0",
            "--render", "png",
        ],
    )
    assert result.exit_code != 0
    assert "--output" in result.output


@pytest.mark.skipif(
    shutil.which("dot") is None,
    reason="graphviz dot not on PATH",
)
def test_cfg_dot_render_writes_png(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    _write_branching_disasm(version_dirpath, "demo", "1.0")
    out_filepath = tmp_path / "graph.png"

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "cfg", "dot-call-graph", "1.0",
            "--render", "png",
            "-o", str(out_filepath),
        ],
    )
    assert result.exit_code == 0, result.output
    assert out_filepath.exists()
    assert out_filepath.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
