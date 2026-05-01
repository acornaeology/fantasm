"""Smoke tests for the fantasm CLI."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from fantasm.cli import main


def test_help_runs() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "fantasm" in result.output.lower()


def test_version_runs() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "fantasm" in result.output.lower()


def test_info_with_unresolved_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FANTASM_PROJECT_ROOT", raising=False)
    runner = CliRunner()
    result = runner.invoke(main, ["info", "--as", "tsv"])
    assert result.exit_code == 0, result.output
    assert "(unresolved)" in result.output


def test_info_with_explicit_project_root(tmp_path: Path) -> None:
    (tmp_path / "fantasm.toml").write_text('name = "demo"\n', encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        main, ["--project-root", str(tmp_path), "info", "--as", "tsv"]
    )
    assert result.exit_code == 0, result.output
    assert str(tmp_path.resolve()) in result.output
    assert "fantasm.toml" in result.output


def test_info_discovers_via_walk_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "fantasm.toml").write_text('name = "discovered"\n', encoding="utf-8")
    nested_dirpath = tmp_path / "a" / "b"
    nested_dirpath.mkdir(parents=True)
    monkeypatch.chdir(nested_dirpath)
    monkeypatch.delenv("FANTASM_PROJECT_ROOT", raising=False)
    runner = CliRunner()
    result = runner.invoke(main, ["info", "--as", "tsv"])
    assert result.exit_code == 0, result.output
    assert str(tmp_path.resolve()) in result.output


def test_env_var_resolves_project_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "fantasm.toml").write_text('name = "envvar"\n', encoding="utf-8")
    monkeypatch.setenv("FANTASM_PROJECT_ROOT", str(tmp_path))
    monkeypatch.chdir(Path.home())
    runner = CliRunner()
    result = runner.invoke(main, ["info", "--as", "tsv"])
    assert result.exit_code == 0, result.output
    assert str(tmp_path.resolve()) in result.output


def test_explicit_overrides_env_var(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    explicit_dirpath = tmp_path / "explicit"
    env_dirpath = tmp_path / "env"
    explicit_dirpath.mkdir()
    env_dirpath.mkdir()
    (explicit_dirpath / "fantasm.toml").write_text('name = "explicit"\n', encoding="utf-8")
    (env_dirpath / "fantasm.toml").write_text('name = "env"\n', encoding="utf-8")
    monkeypatch.setenv("FANTASM_PROJECT_ROOT", str(env_dirpath))
    runner = CliRunner()
    result = runner.invoke(
        main, ["--project-root", str(explicit_dirpath), "info", "--as", "tsv"]
    )
    assert result.exit_code == 0, result.output
    assert str(explicit_dirpath.resolve()) in result.output
    assert str(env_dirpath.resolve()) not in result.output
