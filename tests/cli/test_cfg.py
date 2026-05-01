"""Tests for ``fantasm cfg`` subcommands."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project, write_minimal_disasm


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
