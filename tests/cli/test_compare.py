"""Tests for ``fantasm compare``."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import init_project


class TestCompareCommand:
    def test_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["compare", "--help"])
        assert result.exit_code == 0
        assert "diff" in result.output.lower()

    def test_unknown_version_a(self, tmp_path: Path) -> None:
        runner = CliRunner()
        init_project(tmp_path, runner, "test", "test")
        result = runner.invoke(
            main,
            ["--project-root", str(tmp_path), "compare", "9.99", "8.88"],
        )
        assert result.exit_code != 0
