"""Tests for ``fantasm labels`` subcommands."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project


def _write_inventory_disasm(tmp_path: Path) -> None:
    """Lay down a project with one version + a JSON exercising
    driver labels, sub-labels, env labels, and inbound refs."""
    json_filepath = (
        tmp_path / "versions" / "demo-1.0" / "output" / "demo-1.0.json"
    )
    json_filepath.parent.mkdir(parents=True, exist_ok=True)
    json_filepath.write_text(
        json.dumps(
            {
                "meta": {"load_addr": 0x8000, "end_addr": 0x8100},
                "subroutines": [{"addr": 0x8000, "name": "init"}],
                "external_labels": {"oswrch": 0xFFEE},
                "items": [
                    {
                        "addr": 0x8000,
                        "type": "code",
                        "mnemonic": "lda",
                        "labels": ["init"],
                    },
                    {
                        "addr": 0x8002,
                        "type": "code",
                        "mnemonic": "jsr",
                        "target": 0xFFEE,
                        "labels": [],
                    },
                    {
                        "addr": 0x8005,
                        "type": "code",
                        "mnemonic": "jmp",
                        "target": 0x8000,
                        "labels": ["really_long_label_name_for_audit"],
                    },
                    {
                        "addr": 0x8008,
                        "type": "code",
                        "mnemonic": "rts",
                        "labels": ["c8008"],
                    },
                ],
            }
        )
    )


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


# --- labels list --------------------------------------------------


def test_labels_list_lists_all_labels(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    _write_inventory_disasm(tmp_path)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "list", "1.0", "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "init" in result.output
    assert "oswrch" in result.output
    assert "c8008" in result.output
    assert "really_long_label_name_for_audit" in result.output


def test_labels_list_source_env_only(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    _write_inventory_disasm(tmp_path)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "list", "1.0",
            "--source", "env",
            "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "oswrch" in result.output
    assert "init" not in result.output
    assert "c8008" not in result.output


def test_labels_list_min_length_filter(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    _write_inventory_disasm(tmp_path)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "list", "1.0",
            "--min-length", "20",
            "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "really_long_label_name_for_audit" in result.output
    assert "init" not in result.output


def test_labels_list_match_regex(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    _write_inventory_disasm(tmp_path)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "list", "1.0",
            "--match", "^c[0-9a-f]+$",
            "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "c8008" in result.output
    assert "init" not in result.output
    assert "oswrch" not in result.output


def test_labels_list_invalid_regex_errors(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    _write_inventory_disasm(tmp_path)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "list", "1.0",
            "--match", "[unterminated",
        ],
    )
    assert result.exit_code != 0
    assert "regular expression" in result.output


def test_labels_list_sort_by_len_reverse(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    _write_inventory_disasm(tmp_path)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "list", "1.0",
            "--sort", "len", "--reverse",
            "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    lines = [
        line for line in result.output.splitlines()
        if line and not line.startswith("#")
    ]
    # Longest label first.
    assert lines[0].split("\t")[0] == "really_long_label_name_for_audit"


# --- labels refs --------------------------------------------------


def test_labels_refs_driver_label(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    _write_inventory_disasm(tmp_path)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "refs", "1.0", "init",
        ],
    )
    assert result.exit_code == 0, result.output
    # init is referenced by the jmp at &8005.
    assert "&8005" in result.output
    assert "jmp" in result.output


def test_labels_refs_env_label(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    _write_inventory_disasm(tmp_path)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "refs", "1.0", "oswrch",
        ],
    )
    assert result.exit_code == 0, result.output
    # oswrch is referenced by the jsr at &8002.
    assert "&8002" in result.output
    assert "jsr" in result.output


def test_labels_refs_missing_label_errors(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    _write_inventory_disasm(tmp_path)

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "labels", "refs", "1.0", "no_such_label",
        ],
    )
    assert result.exit_code != 0
    assert "no_such_label" in result.output
