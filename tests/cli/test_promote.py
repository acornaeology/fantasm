"""Tests for ``fantasm promote``."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project, write_minimal_disasm


def test_promote(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")

    version_dirpath = tmp_path / "versions" / "demo-1.0"
    write_minimal_disasm(version_dirpath, "demo", "1.0")

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "promote", "1.0", "--show-all", "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
