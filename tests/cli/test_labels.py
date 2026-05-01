"""Tests for ``fantasm labels`` subcommands."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project


def test_labels_classify(tmp_path: Path) -> None:
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
                {
                    "addr": 0x8000,
                    "type": "code",
                    "mnemonic": "lda",
                    "labels": ["main"],
                },
                {
                    "addr": 0x8002,
                    "type": "code",
                    "mnemonic": "rts",
                    "labels": ["c8002"],
                },
            ],
        })
    )
    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "classify", "1.0", "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "c8002" in result.output


def test_labels_apply_dry_run(tmp_path: Path) -> None:
    runner = CliRunner()
    driver_filepath = tmp_path / "driver.py"
    driver_filepath.write_text(
        "import py8dis\n"
        "\n"
        "# =================== Subroutines ===================\n"
        'subroutine(0x8000, "init")\n'
        "\n"
        "# Code label renames\n"
        'label(0x8010, "first")\n'
        'label(0x8020, "second")\n'
        "\n"
        "# =================== End ===================\n"
        "tail()\n"
    )
    renames_filepath = tmp_path / "renames.toml"
    renames_filepath.write_text(
        'renames = [\n'
        '  { addr = 0x8010, name = "renamed_first" },\n'
        '  { addr = 0x8030, name = "new_label" },\n'
        ']\n'
    )

    result = runner.invoke(
        main,
        [
            "labels", "apply",
            str(driver_filepath), str(renames_filepath),
            "--dry-run",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "renamed_first" in result.output
    assert "new_label" in result.output
    assert "renamed_first" not in driver_filepath.read_text()


def test_labels_apply_in_place(tmp_path: Path) -> None:
    runner = CliRunner()
    driver_filepath = tmp_path / "driver.py"
    driver_filepath.write_text(
        "# Code label renames\n"
        'label(0x8010, "first")\n'
    )
    renames_filepath = tmp_path / "renames.toml"
    renames_filepath.write_text(
        'renames = [{ addr = 0x8010, name = "renamed" }]\n'
    )
    result = runner.invoke(
        main,
        [
            "labels", "apply",
            str(driver_filepath), str(renames_filepath),
            "--in-place",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "renamed" in driver_filepath.read_text()


def test_labels_apply_missing_renames_array(tmp_path: Path) -> None:
    runner = CliRunner()
    driver_filepath = tmp_path / "driver.py"
    driver_filepath.write_text("# Code label renames\n")
    renames_filepath = tmp_path / "renames.toml"
    renames_filepath.write_text("# empty\n")
    result = runner.invoke(
        main,
        [
            "labels", "apply",
            str(driver_filepath), str(renames_filepath),
        ],
    )
    assert result.exit_code != 0
    assert "renames" in result.output
