"""Tests for ``fantasm audit`` subcommands."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project, write_minimal_disasm


class TestAuditSummary:
    def test_runs_with_minimal_json(self, tmp_path: Path) -> None:
        runner = CliRunner()
        init_project(tmp_path, runner, "demo", "demo")
        add_version(tmp_path, runner, "1.0", "demo")

        version_dirpath = tmp_path / "versions" / "demo-1.0"
        write_minimal_disasm(version_dirpath, "demo", "1.0")

        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "audit", "summary", "1.0", "--as", "tsv",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "alpha" in result.output

    def test_missing_json_errors(self, tmp_path: Path) -> None:
        runner = CliRunner()
        init_project(tmp_path, runner, "demo", "demo")
        add_version(tmp_path, runner, "1.0", "demo")
        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "audit", "summary", "1.0",
            ],
        )
        assert result.exit_code != 0
        assert "JSON" in result.output


class TestAuditUndeclared:
    def test_runs(self, tmp_path: Path) -> None:
        runner = CliRunner()
        init_project(tmp_path, runner, "demo", "demo")
        add_version(tmp_path, runner, "1.0", "demo")

        version_dirpath = tmp_path / "versions" / "demo-1.0"
        write_minimal_disasm(version_dirpath, "demo", "1.0")

        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "audit", "undeclared", "1.0", "--as", "tsv",
            ],
        )
        assert result.exit_code == 0, result.output


class TestAuditDetail:
    def test_audit_detail(self, tmp_path: Path) -> None:
        runner = CliRunner()
        init_project(tmp_path, runner, "demo", "demo")
        add_version(tmp_path, runner, "1.0", "demo")

        version_dirpath = tmp_path / "versions" / "demo-1.0"
        write_minimal_disasm(version_dirpath, "demo", "1.0")

        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "audit", "detail", "1.0", "alpha", "--as", "tsv",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "alpha" in result.output
        assert "8000" in result.output

    def test_audit_detail_unknown_target(self, tmp_path: Path) -> None:
        runner = CliRunner()
        init_project(tmp_path, runner, "demo", "demo")
        add_version(tmp_path, runner, "1.0", "demo")

        version_dirpath = tmp_path / "versions" / "demo-1.0"
        write_minimal_disasm(version_dirpath, "demo", "1.0")

        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "audit", "detail", "1.0", "nonexistent",
            ],
        )
        assert result.exit_code != 0
        assert "not found" in result.output
