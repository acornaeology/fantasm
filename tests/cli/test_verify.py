"""Tests for ``fantasm verify``."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project


class TestVerifyCommand:
    def test_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["verify", "--help"])
        assert result.exit_code == 0
        assert "round-trips" in result.output

    def test_no_project_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("FANTASM_PROJECT_ROOT", raising=False)
        runner = CliRunner()
        result = runner.invoke(main, ["verify", "1.0"])
        assert result.exit_code != 0
        assert "no project root" in result.output

    def test_unknown_version(self, tmp_path: Path) -> None:
        runner = CliRunner()
        init_project(tmp_path, runner, "test", "test")
        result = runner.invoke(
            main,
            ["--project-root", str(tmp_path), "verify", "9.99"],
        )
        assert result.exit_code != 0
        assert "not found" in result.output


def test_verify_all_requires_either_arg_or_flag(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path), "verify"],
    )
    assert result.exit_code != 0
    assert "VERSION_ID" in result.output or "--all" in result.output


def test_verify_all_no_versions(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path), "verify", "--all"],
    )
    assert result.exit_code != 0
    assert "no versions found" in result.output


def test_verify_all_skips_missing_files(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    result = runner.invoke(
        main,
        ["--project-root", str(tmp_path), "verify", "--all"],
    )
    assert result.exit_code != 0
    assert "SKIPPED" in result.output
