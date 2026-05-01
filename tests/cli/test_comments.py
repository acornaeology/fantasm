"""Tests for ``fantasm comments`` subcommands."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project, write_minimal_disasm


def test_comments_check_runs_clean(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    write_minimal_disasm(version_dirpath, "demo", "1.0")

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "comments", "check", "1.0", "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output


def test_comments_check_invalid_sub_address(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    write_minimal_disasm(version_dirpath, "demo", "1.0")

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "comments", "check", "1.0", "--sub", "not-hex",
        ],
    )
    assert result.exit_code != 0
    assert "invalid address" in result.output


def test_comments_suggest(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    json_filepath = version_dirpath / "output" / "demo-1.0.json"
    json_filepath.parent.mkdir(exist_ok=True)
    json_filepath.write_text(
        json.dumps({
            "meta": {"load_addr": 0x8000, "end_addr": 0x8100},
            "subroutines": [],
            "items": [
                {"addr": 0x8000, "type": "code", "mnemonic": "pha"},
                {"addr": 0x8001, "type": "code", "mnemonic": "tax"},
                {
                    "addr": 0x8002,
                    "type": "code",
                    "mnemonic": "pla",
                    "comment_inline": "existing",
                },
            ],
        })
    )

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "comments", "suggest", "1.0", "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Save A on stack" in result.output
    assert "Transfer A to X" in result.output
    assert "existing" not in result.output


def test_comments_suggest_invalid_label_hint(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    version_dirpath = tmp_path / "versions" / "demo-1.0"
    json_filepath = version_dirpath / "output" / "demo-1.0.json"
    json_filepath.parent.mkdir(exist_ok=True)
    json_filepath.write_text(
        json.dumps({
            "meta": {"load_addr": 0x8000, "end_addr": 0x8100},
            "subroutines": [],
            "items": [],
        })
    )
    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "comments", "suggest", "1.0",
            "--label-hint", "no-equals-sign",
        ],
    )
    assert result.exit_code != 0
    assert "PATTERN=description" in result.output
