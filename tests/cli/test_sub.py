"""Tests for ``fantasm sub`` subcommands."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main


def test_sub_insert(tmp_path: Path) -> None:
    runner = CliRunner()
    driver_filepath = tmp_path / "driver.py"
    driver_filepath.write_text(
        "import py8dis\n"
        "# =================== Subroutines correspondence ===================\n"
        'subroutine(0x8000, "init")\n'
        'subroutine(0x8100, "later")\n'
        "# =================== End ===================\n"
        "tail()\n"
    )
    result = runner.invoke(
        main,
        [
            "sub", "insert", str(driver_filepath), "$8050",
            "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "8000" in result.output
