"""Tests for ``fantasm annotations`` subcommands."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from fantasm.cli import main

from ._helpers import add_version, init_project


def test_annotations_diff(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    add_version(tmp_path, runner, "1.0", "demo")
    add_version(tmp_path, runner, "2.0", "demo")

    toml_filepath = tmp_path / "fantasm.toml"
    toml_filepath.write_text(
        toml_filepath.read_text()
        + "\n[[versions.entry]]\nid = \"1.0\"\n"
        + "\n[[versions.entry]]\nid = \"2.0\"\nparents = [\"1.0\"]\n"
    )

    rom = bytes([0xA9, 0x01, 0x60, 0xA9, 0x02, 0x60])
    for vid in ("1.0", "2.0"):
        (tmp_path / "versions" / f"demo-{vid}" / "rom" / f"demo-{vid}.rom").write_bytes(rom)

    source_driver = tmp_path / "src.py"
    source_driver.write_text('label(0x8000, "init")\n')
    target_driver = tmp_path / "tgt.py"
    target_driver.write_text('label(0x8000, "boot")\n')

    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "annotations", "diff", "1.0", "2.0",
            "--source-driver", str(source_driver),
            "--target-driver", str(target_driver),
            "--threshold", "1",
            "--as", "tsv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "init" in result.output
    assert "boot" in result.output
    assert "differs" in result.output


def test_annotations_diff_no_graph(tmp_path: Path) -> None:
    runner = CliRunner()
    init_project(tmp_path, runner, "demo", "demo")
    result = runner.invoke(
        main,
        [
            "--project-root", str(tmp_path),
            "annotations", "diff", "1.0", "2.0",
        ],
    )
    assert result.exit_code != 0
    assert "[[versions.entry]]" in result.output
