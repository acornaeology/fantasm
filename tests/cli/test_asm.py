"""Tests for ``fantasm asm`` subcommands."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project


def test_asm_extract(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    asm_filepath = version_dirpath / "output" / "demo-1.0.asm"
    asm_filepath.parent.mkdir(exist_ok=True)
    asm_filepath.write_text(
        "\n.start\n    LDA #$00       ;8000:\n    RTS            ;8002:\n"
    )

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "asm", "extract", "1.0", "$8000",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "LDA" in result.output
