"""Tests for ``fantasm coverage``."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project


def _setup(tmp_path: Path, items, subroutines=()):
    """Boot a demo project and write a JSON disassembly with the given items."""
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    json_filepath = version_dirpath / "output" / "demo-1.0.json"
    json_filepath.parent.mkdir(exist_ok=True)
    json_filepath.write_text(
        json.dumps({
            "meta": {"load_addr": 0x8000, "end_addr": 0x8200},
            "items": list(items),
            "subroutines": list(subroutines),
        })
    )
    return runner


def test_coverage_summary(tmp_path: Path) -> None:
    runner = _setup(
        tmp_path,
        items=[
            {"addr": 0x8000, "type": "code", "mnemonic": "lda",
             "comment_inline": "first"},
            {"addr": 0x8002, "type": "code", "mnemonic": "rts"},
        ],
        subroutines=[{"addr": 0x8000, "name": "main"}],
    )

    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "coverage", "1.0", "--report", "summary", "--as", "tsv"],
    )
    assert result.exit_code == 0, result.output
    # 1 of 2 code items commented → 50.0%.
    assert "50.0%" in result.output
    # The supporting counts surface in the summary table.
    assert "code_items" in result.output
    assert "subroutines" in result.output


def test_coverage_by_page(tmp_path: Path) -> None:
    runner = _setup(
        tmp_path,
        items=[
            {"addr": 0x8000, "type": "code", "mnemonic": "lda",
             "comment_inline": "x"},
            {"addr": 0x8100, "type": "code", "mnemonic": "lda"},
        ],
    )

    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "coverage", "1.0", "--by", "page", "--as", "tsv"],
    )
    assert result.exit_code == 0, result.output
    assert "&8000-&80FF" in result.output
    assert "&8100-&81FF" in result.output


def test_coverage_by_sub(tmp_path: Path) -> None:
    runner = _setup(
        tmp_path,
        items=[
            {"addr": 0x8000, "type": "code", "mnemonic": "lda",
             "comment_inline": "x"},
            {"addr": 0x8002, "type": "code", "mnemonic": "rts"},
        ],
        subroutines=[{"addr": 0x8000, "name": "main"}],
    )

    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path),
         "coverage", "1.0", "--by", "sub", "--as", "tsv"],
    )
    assert result.exit_code == 0, result.output
    # The single sub appears as a group label in the breakdown.
    assert "main" in result.output


def test_coverage_help_lists_by_choices() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["coverage", "--help"])
    assert result.exit_code == 0
    assert "--by" in result.output
    assert "page" in result.output
    assert "sub" in result.output
