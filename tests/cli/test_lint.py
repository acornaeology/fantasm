"""Tests for ``fantasm lint``."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project, write_minimal_disasm


def test_lint_annotations(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    write_minimal_disasm(version_dirpath, "demo", "1.0")

    driver_filepath = tmp_path / "driver.py"
    driver_filepath.write_text(
        'comment(0x8001, "in-range")\n'
        'comment(0x9999, "out-of-range")\n'
    )

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "lint", "1.0", str(driver_filepath), "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "9999" in result.output
