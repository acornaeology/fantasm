"""Tests for the ``fantasm project`` CLI command group."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
from click.testing import CliRunner

from fantasm.cli import main


# --- project init -------------------------------------------------


class TestProjectInit:
    def test_init_writes_fantasm_toml(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "project",
                "init",
                "--name", "acorn-nfs",
                "--prefix", "anfs",
                "--prefix", "nfs",
                "--at", str(tmp_path),
            ],
        )
        assert result.exit_code == 0, result.output
        toml = tmp_path / "fantasm.toml"
        assert toml.exists()
        parsed = tomllib.loads(toml.read_text())
        assert parsed["project"]["name"] == "acorn-nfs"
        assert parsed["versions"]["prefixes"] == ["anfs", "nfs"]

    def test_init_creates_versions_dir(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "project", "init",
                "--name", "x",
                "--at", str(tmp_path),
            ],
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "versions").is_dir()

    def test_init_default_prefix_is_name(self, tmp_path: Path) -> None:
        runner = CliRunner()
        runner.invoke(
            main,
            ["project", "init", "--name", "acorn-adfs", "--at", str(tmp_path)],
        )
        parsed = tomllib.loads((tmp_path / "fantasm.toml").read_text())
        assert parsed["versions"]["prefixes"] == ["acorn-adfs"]

    def test_init_refuses_overwrite_without_force(
        self, tmp_path: Path
    ) -> None:
        runner = CliRunner()
        runner.invoke(
            main,
            ["project", "init", "--name", "x", "--at", str(tmp_path)],
        )
        result = runner.invoke(
            main,
            ["project", "init", "--name", "x", "--at", str(tmp_path)],
        )
        assert result.exit_code != 0
        assert "already exists" in result.output

    def test_init_force_overwrites(self, tmp_path: Path) -> None:
        runner = CliRunner()
        runner.invoke(
            main,
            ["project", "init", "--name", "old", "--at", str(tmp_path)],
        )
        result = runner.invoke(
            main,
            [
                "project", "init",
                "--name", "new",
                "--at", str(tmp_path),
                "--force",
            ],
        )
        assert result.exit_code == 0, result.output
        parsed = tomllib.loads((tmp_path / "fantasm.toml").read_text())
        assert parsed["project"]["name"] == "new"


# --- project add --------------------------------------------------


class TestProjectAdd:
    def _make_project(
        self, tmp_path: Path, runner: CliRunner, prefixes: list[str]
    ) -> None:
        args = ["project", "init", "--name", "test", "--at", str(tmp_path)]
        for p in prefixes:
            args.extend(["--prefix", p])
        result = runner.invoke(main, args)
        assert result.exit_code == 0, result.output

    def test_add_creates_version_dir(self, tmp_path: Path) -> None:
        runner = CliRunner()
        self._make_project(tmp_path, runner, ["anfs", "nfs"])

        result = runner.invoke(
            main,
            ["--project-root", str(tmp_path), "project", "add", "3.10"],
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "versions" / "anfs-3.10").is_dir()
        assert (tmp_path / "versions" / "anfs-3.10" / "rom").is_dir()
        assert (tmp_path / "versions" / "anfs-3.10" / "output").is_dir()

    def test_add_with_explicit_prefix(self, tmp_path: Path) -> None:
        runner = CliRunner()
        self._make_project(tmp_path, runner, ["anfs", "nfs"])

        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "project", "add", "3.10",
                "--prefix", "nfs",
            ],
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "versions" / "nfs-3.10").is_dir()

    def test_add_without_project_root_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("FANTASM_PROJECT_ROOT", raising=False)
        runner = CliRunner()
        result = runner.invoke(main, ["project", "add", "3.10"])
        assert result.exit_code != 0
        assert "no project root" in result.output

    def test_add_existing_fails(self, tmp_path: Path) -> None:
        runner = CliRunner()
        self._make_project(tmp_path, runner, ["anfs"])
        runner.invoke(
            main,
            ["--project-root", str(tmp_path), "project", "add", "3.10"],
        )
        result = runner.invoke(
            main,
            ["--project-root", str(tmp_path), "project", "add", "3.10"],
        )
        assert result.exit_code != 0
        assert "already exists" in result.output


# --- project list -------------------------------------------------


class TestProjectList:
    def test_list_shows_added_versions(self, tmp_path: Path) -> None:
        runner = CliRunner()
        runner.invoke(
            main,
            [
                "project", "init",
                "--name", "test",
                "--prefix", "anfs",
                "--prefix", "nfs",
                "--at", str(tmp_path),
            ],
        )
        runner.invoke(
            main,
            ["--project-root", str(tmp_path), "project", "add", "3.10"],
        )
        runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "project", "add", "4.18",
                "--prefix", "nfs",
            ],
        )

        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "project", "list",
                "--as", "tsv",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "anfs" in result.output
        assert "3.10" in result.output
        assert "nfs" in result.output
        assert "4.18" in result.output

    def test_list_with_no_project_root_shows_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("FANTASM_PROJECT_ROOT", raising=False)
        runner = CliRunner()
        result = runner.invoke(main, ["project", "list", "--as", "tsv"])
        assert result.exit_code == 0, result.output
        # Empty table, just headers.
        assert "Prefix" in result.output

    def test_list_empty_versions_dir(self, tmp_path: Path) -> None:
        runner = CliRunner()
        runner.invoke(
            main,
            ["project", "init", "--name", "test", "--at", str(tmp_path)],
        )
        result = runner.invoke(
            main,
            [
                "--project-root", str(tmp_path),
                "project", "list",
                "--as", "tsv",
            ],
        )
        assert result.exit_code == 0, result.output
